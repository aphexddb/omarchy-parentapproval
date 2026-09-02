# Trust model

Pairing is the security boundary. An `allow` is an Ed25519 signature the
laptop verifies against the public key it enrolled at pairing. Requests are
single-use. The daemon re-derives the signed message from stored fields, so
the phone cannot swap the command after the parent has seen it.

That core holds against a compromised laptop and a passive network. It does
**not** hold against whoever controls the origin that serves the parent PWA.

## The relay is the phone's code origin

The hosted page (`index.html`, `app.js`, `nacl.min.js`, `sha256.min.js`) is
the program that can use the parent's private key in IndexedDB. A hostile or
compromised relay can serve JavaScript that reads that key, or that silently
signs an `allow`. The default origin `https://parentapprovals.com` is therefore
a single trust root for every family that uses it.

Self-host for high-assurance use. The laptop already honors
`OMARCHY_PARENTAPPROVAL_RELAY`. The relay process honors `RELAY_PUBLIC_URL`.
See [`deploy/relay/README.md`](../deploy/relay/README.md).

The signing libraries are hash-pinned with Subresource Integrity in
`web/index.html`. Release hashes for the PWA files live in
[`web-assets.md`](web-assets.md). After pairing, a parent can fetch those
files and check they match a release.

A silently swapped `app.js` is still possible if the attacker also changes
`index.html` (SRI lives there). A signed service worker is the longer-term
mitigation; it is not shipped yet.

## What the relay can and cannot do

| Actor | Can forge an `allow`? | Can see command text? | Can replace phone code? |
|---|---|---|---|
| Compromised laptop | No (key is on the phone) | Yes (it created the ask) | No |
| Passive network | No (TLS to the relay) | No (TLS + sealed ask) | No |
| Relay operator | Yes, by serving hostile JS | No (user/cwd/cmd/host sealed to the phone) | Yes |

The relay holds only parent public keys. It cannot *itself* sign. Its power
is that it is the code-delivery point and the message bus.

Ask fields `user`, `cwd`, `cmd`, and `host_name` are NaCl-boxed to each paired
phone so a hosted relay proxies opaque blobs. Approvals are still Ed25519 over
`cmd_hash` of the plaintext the phone decrypted. The relay still sees metadata
(`rid`, `service`, match digits, timing). Web-push bodies are generic and do
not include the command. Self-host if the remaining metadata is too much.
