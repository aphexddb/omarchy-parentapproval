# Parent Approval

Your child wants to install something. You are in the kitchen, or in a meeting. You should not have to walk over, take the keyboard, and type `sudo`!

This is a parent-phone approval gate for [Omarchy](https://omarchy.org/) kids accounts. Pair once. Add the page to your Home Screen on your phone and allow notifications. The next time a child account needs to ask for permissions to do something, your phone buzzes, shows the command, and you approve or deny. The child never learns a sudo password, and your life is easier. 

A community extra for Omarchy: for parents, by parents.

Agents: load [SKILL.md](default/agents/skills/parentapproval/SKILL.md) (or run `sudo parentapproval install-skills`).

Install:

```bash
curl -fsSL https://raw.githubusercontent.com/aphexddb/omarchy-parentapproval/main/install.sh | bash
```

First time setup after the package is installed:
```bash
sudo parentapproval pair
sudo parentapproval setup-kid milo
```

Example of asking for approval (no side effects!)
```bash
parentapproval ask --cmd "sudo id"
```

## How it works

1. **You pair once**, sitting at the laptop. Run `sudo parentapproval pair` and scan the pairing URL. The phone generates an Ed25519 key and keeps the private half. The laptop stores only the public half. The 6-digit code is derived from that key — a swapped key changes the digits. Confirm the code on the phone (or type those digits on the laptop overlay). The offering phone's name is shown so you can see whose key you are about to enroll.    
2. **Add the page to Home Screen, tap Allow notifications.** the pair command waits until notifications are on, then exits. After that the phone is a now a parent for this machine.
3. **The kid hits sudo** (or a polkit prompt: pkexec, disks, package installs). They are in the `omarchy-kids` group, so PAM does not accept their login password. Login itself never phones a parent. The laptop asks the relay to notify paired phones. A polkit prompt stays bone stock — no parentapproval QR on that dialog. The QR card is for sudo TTY, `ask`, and pairing only.
4. **Your phone buzzes.** Check the command and the match code, tap Approve. The phone signs the request based on the private key only the phone has, the computer verifies against the enrolled public key.

Why this method vs TOTP? a kid who photographs an enrollment QR would own sudo forever. There are no inbound firewall holes, phones speak HTTPS to the relay, and computer dials outbound WSS. **The approval path is only for `omarchy-kids`.**



## Install

```bash
curl -fsSL https://raw.githubusercontent.com/aphexddb/omarchy-parentapproval/main/install.sh | bash
```

That clones the repo, builds the package, and installs it with pacman. From a checkout, the same path is:

```bash
./scripts/dev-install
```

To remove (package, overlay, skill links, daemon state):

```bash
./scripts/dev-uninstall
```

Teach coding agents the CLI:

```bash
sudo parentapproval install-skills
```

That symlinks the skill into the parent’s and kids’ agent dirs (`~/.agents/skills`, `~/.claude/skills`, `~/.codex/skills`, `~/.pi/agent/skills`, `~/.gemini/config/skills`, and `~/.grok/skills`). `setup-kid` does the same for the kid.

## Relay

Default origin: **https://parentapprovals.com**. That origin is the phone's **code trust root**: it serves the PWA that holds the parent private key. A compromised relay can exfiltrate the key or silently sign an allow. The cryptographic core still stops a compromised *laptop* and a passive network.

High-assurance families should self-host. See [trust model](docs/trust-model.md) for more information.

## Try it without a kid account

Unprivileged (`--dev` is local HTTP, no PAM):

```bash
parentapproval daemon --dev      # terminal 1
sudo parentapproval pair --dev   # terminal 2, scan
parentapproval ask --dev --cmd "pacman -S cowsay"
```

Headless pair + allow/deny against the production relay image (no phone):

```bash
make smoke
```

That builds `Dockerfile`, starts an isolated compose project on loopback, and drives a Go fake-phone over the same HTTP the PWA uses (`/p/{token}`, key-bound SAS, phone confirm, sealed ask, handoff, `/v1/watch` with a one-time nonce, allow/deny). `make test` does not start Docker.

Against a local relay:

```bash
make relay
PORT=8080 RELAY_PUBLIC_URL=http://127.0.0.1:8080 RELAY_DATA=/tmp/parentapproval-data \
  ./bin/parentapproval-relay
parentapproval daemon --dev --relay http://127.0.0.1:8080
```

Against the installed systemd daemon (phone already paired):

```bash
parentapproval ask --cmd "pacman -S cowsay"
```

After a parent approves, the daemon runs that command as root. No sudo password.

## Commands

| Command | What it does |
|---|---|
| `parentapproval ask --cmd "…"` | Ask a parent; daemon runs the command as root |
| `sudo parentapproval pair` | Pair a parent phone |
| `sudo parentapproval setup-kid NAME` | Creates a user (or adds them to omarchy-kids) and sets a login password. That password cannot sudo. |
| `sudo parentapproval disable` | Remove PAM hooks without uninstalling |
| `parentapproval status` | Host id, relay, paired phones |
| `sudo parentapproval revoke DEVICE_ID` | Drop a phone |
| `sudo parentapproval doctor` | Check PAM order (including FIDO/fingerprint sufficient lines), daemon, relay |
| `sudo parentapproval install-skills` | Symlink the agent skill (parent + all kids) |
| `parentapproval daemon [--dev] [--relay URL]` | The service |

`parentapproval --help` is the flag-level source of truth.

## Releases

```bash
./scripts/stamp-version v1.2.3
git add VERSION PKGBUILD
git commit -m "Release v1.2.3"
git tag -a v1.2.3 -m "v1.2.3"
git push origin HEAD v1.2.3
```

GoReleaser publishes Linux amd64 and arm64 archives and a `parentapproval-bin` AUR package (systemd unit, sysusers, sudoers, overlay, skill). The in-tree `PKGBUILD` stays a source checkout recipe. AUR push needs repo secret `AUR_KEY`. Dry-run: `make release-snapshot`.

## What this is not

- Not a login or lock-screen replacement. The kid still unlocks the session with their own password.
- Not Omarchy's 15-minute passwordless sudo. That feature is for agents acting as *you*.
- Not a kid-proof kernel. Once they have a root shell, the game is over, same as any local privilege product.

Phone lock and OS biometrics are the residual control if the kid gets your unlocked phone. Same as Ask to Buy.

## Protocol

Ed25519 over canonical bytes, not JSON. Specified in [`docs/SPEC.md`](docs/SPEC.md). 