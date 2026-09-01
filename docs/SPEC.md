# omarchy-approve v1

The QR is a capability *request*. Pairing is the security boundary.

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

## Pairing

QR: `http://<lan-ip>:7421/pair/<sid>`

`POST /pair/{sid}` with `{v, device_id, name, alg:"Ed25519", pubkey}`. The laptop must confirm the 6-digit SAS shown on both screens before the pubkey is stored. `GET /pair/{sid}/wait` long-polls until that confirm.

## Approval

QR: `http://<lan-ip>:7421/a/<rid>`

`GET /a/{rid}` (`Accept: application/json`) returns the request. `POST /a/{rid}/decision` with `{v, device_id, decision, sig}`. The server rebuilds canonical bytes from **stored** fields and verifies against the enrolled parent pubkey. First valid decision spends `rid`. Unauthenticated `deny` is allowed (kid cancel / panic). Unauthenticated `allow` is not.

TTL 120s. One outstanding request per user; a new one cancels the old.

## PAM

Kids (`omarchy-kids`) on `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`:

```
auth [success=1 default=ignore] pam_succeed_if.so quiet user notingroup omarchy-kids
auth [success=done default=die] pam_exec.so seteuid stdout /usr/bin/omarchy-qr-sudo pam
```

Non-kids skip the helper and keep fingerprint / FIDO / password. Kids never fall through to `pam_unix`. This block must stay **above** `pam_fprintd` / `pam_u2f` so an enrolled kid print cannot sudo.

Sudoers:

```
Defaults:%omarchy-kids timestamp_timeout=0
%omarchy-kids ALL=(ALL:ALL) ALL
```

The daemon never runs the command. PAM success is the only grant.

## HTTP

Port 7421, RFC1918 only, bound only while a pairing session or a live request exists. No TLS in v1: the secret never crosses the LAN, only pubkeys and signatures.
