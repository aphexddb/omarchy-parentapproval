# parentapproval v1

The QR / pairing URL is a capability *request*. Pairing is the security boundary.

## Canonical signature

The phone signs these bytes, UTF-8, with a trailing newline after every field including the last:

```
OMARCHY-APPROVE/1
<decision>
<rid hex>
<nonce base64url>
<exp unix seconds>
<host_id base64url>
<user>
<service>
<cmd_hash base64url>
```

`decision` is exactly `allow` or `deny`. `cmd_hash` is SHA-256 of `user\0service\0cwd\0cmd\0`. The daemon hashes the stored request; the phone hashes the fields it displayed. If they differ, the phone refuses to sign.

Pure Ed25519 (not ph, not ctx). Keys and signatures are raw bytes in unpadded base64url. `rid` is 16 random bytes, lowercase hex.

The prefix `OMARCHY-APPROVE/1` is frozen so already-paired phones keep working.

## Topology

```
Phone --HTTPS--> relay (parentapprovals.com) <--WSS outbound-- laptop daemon
Unix socket PAM / ask / pair CLI stays on the laptop.
```

Default public origin: `https://parentapprovals.com`. Configurable via
`OMARCHY_PARENTAPPROVAL_RELAY` (laptop) and `RELAY_PUBLIC_URL` (relay).
The relay container does not terminate TLS.

The relay is the phone's code origin and a primary trust root. It cannot
forge an Ed25519 `allow` with only public keys, but it can serve JavaScript
that uses the key in IndexedDB. Self-host for high-assurance use.
See [`trust-model.md`](trust-model.md). Crypto libraries are SRI-pinned;
asset hashes are in [`web-assets.md`](web-assets.md).

## Pairing

Opaque token URL: `https://parentapprovals.com/p/<token>`

`GET /p/{token}/meta` returns `{kind, sid|rid}`. The PWA then calls the
existing pair/ask routes on the same origin.

`POST /pair/{sid}` with `{v, device_id, name, alg:"Ed25519", pubkey}`. The 6-digit SAS
is six decimal digits from SHA-256 of these bytes (trailing newline after every
field, including the last):

```
OMARCHY-SAS/1
<sid>
<pubkey base64url>
```

A substituted key yields different digits. A second offer while one is pending
is rejected (no last-writer-wins swap). The phone computes the SAS locally from
its key; the laptop shows the offering device name. Laptop overlay confirm
requires typing the 6 digits from the phone (a bare Y does not enroll). The
phone confirms with `{device_id, sas}` (`POST /pair/{sid}/confirm`). The pubkey
is stored only after that confirm. `GET /pair/{sid}/wait` long-polls until then.

After confirm, `parentapproval pair` waits until the phone has posted `POST /push/subscribe` (notifications allowed in the Home Screen app), then exits. The laptop sends `{op:expect-push}` and polls `{op:push-ready}`. The relay pushes `{op:subscribed}` when the phone subscribes.

Safari pairing cannot copy into the iOS Home Screen app (partitioned storage). After pair the phone POSTs `/p/{token}/handoff` with the pairing record. The Home Screen icon is installed from that pairing URL (`start_url` `/p/{token}?homescreen=1`) so it can GET the handoff, then subscribe.

The relay looks up which laptop owns `sid`/`rid` (from WSS `open`) and proxies the HTTP request over that connection. If the laptop is disconnected: HTTP 502 with a JSON error.

## Approval

`GET /a/{rid}` (`Accept: application/json`) returns the request. Cleartext
`user`, `cwd`, `cmd`, and `host_name` are omitted. Instead `sealed` is a map of
`device_id` → NaCl box of `{"user","cwd","cmd","host_name"}` (X25519 from the
enrolled Ed25519 key; blob is `ephemeral_pub || nonce || ciphertext`, unpadded
base64url). The phone decrypts, displays, and hashes those fields. `POST /a/{rid}/decision` with `{v, device_id, decision, sig}`. The server rebuilds canonical bytes from **stored** fields and verifies against the enrolled parent pubkey. First valid decision spends `rid`. Unauthenticated `deny` is allowed (kid cancel / panic). Unauthenticated `allow` is not.

TTL 120s. One outstanding request per user; a new one cancels the old.

`create` over the unix socket sets `user` from `SO_PEERCRED` for
unprivileged callers (the request field is ignored). Root may still pass
`user` (PAM helper that did not drop privs). `pending.json` is `0600`.

After `create`, the laptop sends `notify` on the WSS so the relay web-pushes paired phones.
An already-open PWA does not wait for that push: it long-polls `GET /v1/watch` (signed;
see below) and the relay (or local `--dev` HTTP) returns the ask as soon as it is opened.

## Host WSS (`/v1/host`)

Laptop dials outbound. Server `{op:challenge, nonce}` (nonce is 32 random bytes, unpadded base64url). Client `{op:hello, host_id, host_name, pubkey, sig}` where `sig = Ed25519(hostkey, nonce_bytes)` and `host_id` is `B64(pubkey)`. Then JSON RPC:

- `{op:open, id, kind:pair|ask, sid|rid}` → `{op:opened, id, token}`
- `{op:proxy, id, method, path, header, body}` → laptop runs existing HTTP handlers via `httptest.NewRecorder` and replies `{op:proxy-res, id, status, header, body}`
- `{op:notify, host_id, device_id?, title, body, url}` → web-push
- `{op:expect-push, id, device_id}` laptop is waiting for this phone to enable notifications
- `{op:push-ready, id, device_id}` → `{op:push-ready, id, ready}` (`device_id` empty = any sub for this host)
- `{op:subscribed, host_id, device_id}` laptop receives when a phone `POST /push/subscribe`s
- `{op:parent, device_id, pubkey}` laptop enrolls a paired phone so `/v1/watch` can verify it
- `{op:revoke-parent, device_id}` drop that phone's watch key

`--dev` without `--relay` still serves local HTTP on `protocol.ListenPort` (17421) with no firewall.

## Phone watch (`GET /v1/watch`)

`host_id` is `B64(host pubkey)`, not the machine hostname. Hostnames collide;
host keys do not. Knowing `host_id` still must not let a stranger watch asks.

The open PWA long-polls one host at a time with a paired-phone signature:

```
GET /v1/watch?host_id=&device_id=&nonce=&exp=&sig=
```

`sig` is Ed25519 over these bytes (trailing newline after every field):

```
OMARCHY-WATCH/1
<host_id>
<device_id>
<nonce base64url>
<exp unix seconds>
```

`nonce` is 16 random bytes, unpadded base64url, unique per poll. A captured
signature cannot be replayed: the server remembers `(device_id, nonce)` until
`exp`. `exp` must be in `(now, now+60]`. The relay verifies against the pubkey the
laptop enrolled (`{op:parent}`). Local `--dev` HTTP verifies against the
daemon's stored parent. Missing fields are 400; a bad or unknown key is 401
and does not wait.

The server holds an authorized poll for ~25s.

- If that host has a live ask: `{kind:"ask", rid, url}` immediately.
- When an ask is `open`ed (or `notify` arrives) for that host, the hold
  returns the same JSON.
- Otherwise `{kind:"idle"}` and the PWA polls again.

`url` is the pairing-token page (`/p/{token}`) on the relay, or `/a/{rid}`
on local `--dev` HTTP. The page then loads `GET /a/{rid}` as usual.

Push still fires for a closed or backgrounded phone. If a visible window is
already open, the service worker `postMessage`s the ask URL and skips the
OS notification.

## PAM

The package install writes these hooks (and `/etc/sudoers.d/omarchy-kids`).
Uninstall reverses them: unpatches PAM and removes the sudoers drop-in.
Kid login accounts are left in place.

Kids (`omarchy-kids`) on `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`.
`parentapproval pam` refuses login PAM services (`login`, `sddm`, `gdm`, …).
The command shown to the parent is the sudo/pkexec argv after only a
*leading* `sudo`/`pkexec` token (and a following `--`). A later argument
whose basename is `sudo` is displayed as-is, including a resolved path,
so a payload named `sudo` cannot hide behind a benign-looking command.

Ad-hoc polkit (pkexec, disks, packagekit — not display-manager or
`login1.create-session`) uses `/usr/share/polkit-1/rules.d/50-parentapproval.rules`
so kids `AUTH_SELF` instead of `auth_admin`. The session unit
`parentapproval-polkit.service` registers an agent for `omarchy-kids` only:
it phones the parent with the polkit command from `command_line` /
`program` / the action message and waits with **no laptop QR, overlay, or
imv**. After allow, the agent completes `polkit-agent-helper-1`; PAM
redeems the one-shot grant so the parent is not asked twice. The grant is
bound to the polkit action id and cookie; `RedeemService` must present
both. Wheel sessions leave the Omarchy password agent in place. A polkit
prompt stays bone stock — `parentapproval pam` must not write a QR to
stdout (that would become PAM_TEXT_INFO on the stock dialog).

Kids (`omarchy-kids`) on `/etc/pam.d/sudo`:

```
auth [success=1 default=ignore] pam_succeed_if.so quiet user notingroup omarchy-kids
auth [success=done default=die] pam_exec.so seteuid stdout /usr/bin/parentapproval pam
```

Kids on `/etc/pam.d/polkit-1` include `/etc/pam.d/parentapproval-polkit`
instead: the same `pam_succeed_if` / `pam_exec` pair, **without** the
`stdout` flag.

Non-kids skip the helper and keep fingerprint / FIDO / password. Kids never fall through to `pam_unix`. The sudo auth lines live in `/etc/pam.d/parentapproval`; `sudo` `auth include`s that file at the top and `polkit-1` includes `parentapproval-polkit`. `apply-hooks` rewrites the includes and re-hoists the include line so a later `1i auth sufficient pam_u2f.so` / `pam_fprintd.so` (Omarchy's fingerprint/FIDO setup scripts) does not win. `doctor` fails if any `auth sufficient` appears above the include. After enabling fingerprint or FIDO on a kid machine, re-run `sudo parentapproval apply-hooks`.

Sudoers:

```
Defaults:%omarchy-kids timestamp_timeout=0
%omarchy-kids ALL=(ALL:ALL) ALL
```

PAM success is the grant for `sudo`. After `ask` allow, the root daemon
runs the approved command itself (`sh -c`) so the kid is not prompted
for a sudo password. Allow also mints a one-shot grant PAM can redeem
if something still calls sudo for the same command.
