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

`POST /pair/{sid}` with `{v, device_id, name, alg:"Ed25519", pubkey}`. The laptop must confirm the 6-digit SAS shown on both screens before the pubkey is stored. `GET /pair/{sid}/wait` long-polls until that confirm.

The relay looks up which laptop owns `sid`/`rid` (from WSS `open`) and proxies the HTTP request over that connection. If the laptop is disconnected: HTTP 502 with a JSON error.

## Approval

`GET /a/{rid}` (`Accept: application/json`) returns the request. `POST /a/{rid}/decision` with `{v, device_id, decision, sig}`. The server rebuilds canonical bytes from **stored** fields and verifies against the enrolled parent pubkey. First valid decision spends `rid`. Unauthenticated `deny` is allowed (kid cancel / panic). Unauthenticated `allow` is not.

TTL 120s. One outstanding request per user; a new one cancels the old.

After `create`, the laptop sends `notify` on the WSS so the relay web-pushes paired phones.

## Host WSS (`/v1/host`)

Laptop dials outbound. Server `{op:challenge, nonce}` (nonce is 32 random bytes, unpadded base64url). Client `{op:hello, host_id, host_name, pubkey, sig}` where `sig = Ed25519(hostkey, nonce_bytes)` and `host_id` is `B64(pubkey)`. Then JSON RPC:

- `{op:open, id, kind:pair|ask, sid|rid}` → `{op:opened, id, token}`
- `{op:proxy, id, method, path, header, body}` → laptop runs existing HTTP handlers via `httptest.NewRecorder` and replies `{op:proxy-res, id, status, header, body}`
- `{op:notify, host_id, device_id?, title, body, url}` → web-push

`--dev` without `--relay` still serves local HTTP on `protocol.ListenPort` (17421) with no firewall.

## PAM

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
