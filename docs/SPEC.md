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

## Pairing

Opaque token URL: `https://parentapprovals.com/p/<token>`

`GET /p/{token}/meta` returns `{kind, sid|rid}`. The PWA then calls the
existing pair/ask routes on the same origin.

`POST /pair/{sid}` with `{v, device_id, name, alg:"Ed25519", pubkey}`. Both screens show the same 6-digit SAS. The phone confirms (`POST /pair/{sid}/confirm`); the laptop overlay Y is a fallback. The pubkey is stored only after that confirm. `GET /pair/{sid}/wait` long-polls until then.

After confirm, `parentapproval pair` waits until the phone has posted `POST /push/subscribe` (notifications allowed in the Home Screen app), then exits. The laptop sends `{op:expect-push}` and polls `{op:push-ready}`. The relay pushes `{op:subscribed}` when the phone subscribes.

Safari pairing cannot copy into the iOS Home Screen app (partitioned storage). After pair the phone POSTs `/p/{token}/handoff` with the pairing record. The Home Screen icon is installed from that pairing URL (`start_url` `/p/{token}?homescreen=1`) so it can GET the handoff, then subscribe.

The relay looks up which laptop owns `sid`/`rid` (from WSS `open`) and proxies the HTTP request over that connection. If the laptop is disconnected: HTTP 502 with a JSON error.

## Approval

`GET /a/{rid}` (`Accept: application/json`) returns the request. `POST /a/{rid}/decision` with `{v, device_id, decision, sig}`. The server rebuilds canonical bytes from **stored** fields and verifies against the enrolled parent pubkey. First valid decision spends `rid`. Unauthenticated `deny` is allowed (kid cancel / panic). Unauthenticated `allow` is not.

TTL 120s. One outstanding request per user; a new one cancels the old.

After `create`, the laptop sends `notify` on the WSS so the relay web-pushes paired phones.
An already-open PWA does not wait for that push: it long-polls `GET /v1/watch?host_id=…`
and the relay (or local `--dev` HTTP) returns the ask as soon as it is opened.

## Host WSS (`/v1/host`)

Laptop dials outbound. Server `{op:challenge, nonce}` (nonce is 32 random bytes, unpadded base64url). Client `{op:hello, host_id, host_name, pubkey, sig}` where `sig = Ed25519(hostkey, nonce_bytes)` and `host_id` is `B64(pubkey)`. Then JSON RPC:

- `{op:open, id, kind:pair|ask, sid|rid}` → `{op:opened, id, token}`
- `{op:proxy, id, method, path, header, body}` → laptop runs existing HTTP handlers via `httptest.NewRecorder` and replies `{op:proxy-res, id, status, header, body}`
- `{op:notify, host_id, device_id?, title, body, url}` → web-push
- `{op:expect-push, id, device_id}` laptop is waiting for this phone to enable notifications
- `{op:push-ready, id, device_id}` → `{op:push-ready, id, ready}` (`device_id` empty = any sub for this host)
- `{op:subscribed, host_id, device_id}` laptop receives when a phone `POST /push/subscribe`s

`--dev` without `--relay` still serves local HTTP on `protocol.ListenPort` (17421) with no firewall.

## Phone watch (`GET /v1/watch`)

The open PWA long-polls with one or more `host_id` query params (the paired
laptops in IndexedDB). The server holds for ~25s.

- If that host has a live ask: `{kind:"ask", rid, url}` immediately.
- When an ask is `open`ed (or `notify` arrives) for a watched host, the hold
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

Kids (`omarchy-kids`) on `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`:

```
auth [success=1 default=ignore] pam_succeed_if.so quiet user notingroup omarchy-kids
auth [success=done default=die] pam_exec.so seteuid stdout /usr/bin/parentapproval pam
```

Non-kids skip the helper and keep fingerprint / FIDO / password. Kids never fall through to `pam_unix`. This block must stay **above** `pam_fprintd` / `pam_u2f` so an enrolled kid print cannot sudo.

Sudoers:

```
Defaults:%omarchy-kids timestamp_timeout=0
%omarchy-kids ALL=(ALL:ALL) ALL
```

PAM success is the grant for `sudo`. After `ask` allow, the root daemon
runs the approved command itself (`sh -c`) so the kid is not prompted
for a sudo password. Allow also mints a one-shot grant PAM can redeem
if something still calls sudo for the same command.
