# Trust model

`parentapproval` lets a paired parent phone approve a kid's `sudo`, or a call to `parentapproval ask` for arbitrary commands without ever putting a password or the signing key on the kid's computer. Only a valid Ed25519 signature from a paired phone can turn a request into an approval:

![Parent phone holds the private key; the relay and laptop hold only public keys](trust-model.png)

The phone signs `allow`/`deny`. The relay proxies and pushes but sees only public keys. The laptop daemon verifies signatures and runs the command as root. It never signs anything. A valid approval can only be produced by the paired phone (left side of that diagram).

## Principles

**Key isolation.** The private key is generated on the phone and never leaves it. The laptop and relay store only the public half. A fully compromised laptop still cannot produce an approval.

**Canonical signing.** Signatures are Ed25519 over a fixed byte string, not JSON, each prefixed with its purpose:
- `OMARCHY-APPROVE/1` for decisions
- `OMARCHY-WATCH/1` for live-ask polling
Fixed bytes remove canonicalization ambiguity, and distinct prefixes prevent one signature being reused for another protocol.

**Server rebuilds the message.** The daemon verifies each signature over the fields it has *stored*, never over client input. A decision therefore cannot be retargeted to a different command than the one the phone was shown.

**Single-use requests.** Each request id (`rid`) is 128 bits of randomness with a 120-second TTL, and only one request per user is outstanding at a time. The first valid decision spends the `rid`, any replay is refused.

**Tamper check on the phone.** Before signing, the PWA recomputes `cmd_hash` from the request it received and refuses to sign on a mismatch, catching an alteration of the request in transit.

**Hardened PAM helper.** The `pam` helper ignores `--dev` and environment overrides and pins the production socket and state paths. `pam_exec` also does not forward the kid's environment to the helper. Both are defense in depth against a kid-controlled socket or environment.

**Safe defaults.** An unauthenticated `deny` is accepted (so a kid can cancel or panic-stop), but an unauthenticated `allow` never is. Production runs no inbound listener, the laptop dials the relay outbound over WSS.

**Peer-credential gating.** Pairing and revocation require a local, non-kid, connection, checked via `SO_PEERCRED`; members of `omarchy-kids` are rejected.

## What this does not cover

The model protects against a compromised laptop and a passive network, not against a compromised relay origin (which serves the PWA and crypto code) or a stolen, unlocked parent phone. See [`SPEC.md`](SPEC.md) for the wire format and
protocol details.

You can, and should run your own relay! The default relay (parentapprovals.com) uses the Dockerfile in this repo.
