# Parent Approval

The kid wants Steam. You are in the kitchen. You should not have to walk over, take the keyboard, and type `sudo`.

This is a parent-phone approval gate for [Omarchy](https://omarchy.org/) kids accounts. Pair once. Add the page to your Home Screen. Allow notifications. Next time a child account needs to ask for permissions to do something, your phone buzzes, shows the command, and you approve or deny. The child never learns a sudo password, and **opening the request on an unpaired phone does nothing**.

A community extra for Omarchy.

Agents: load [`default/agents/skills/parentapproval/SKILL.md`](SKILL.md) (or run `sudo parentapproval install-skills`).

first time setup (after the package is installed)
```bash
sudo parentapproval pair
sudo parentapproval setup-kid milo
```

asking for approval
```bash
parentapproval ask --cmd "pacman -S cowsay"
```

## How it works

1. **You pair once**, sitting at the laptop. Scan the pairing URL. The phone generates an Ed25519 key and keeps the private half. The laptop stores only the public half. Both screens show the same 6-digit code; confirm it on the phone so a stranger cannot swap in their own key.    
2. **Add the page to Home Screen, tap Allow notifications.** `parentapproval pair` waits until notifications are on, then exits. After that the phone is a parent for this machine.
3. **The kid hits sudo** (or a polkit prompt). They are in the `omarchy-kids` group, so PAM does not accept their login password. The laptop asks the relay to notify paired phones.
4. **Your phone buzzes.** Check the command and the match code, tap Approve. The phone signs the request the daemon already knows. One invocation, then it is spent. Replay is refuse.

Why this method vs TOTP? a kid who photographs an enrollment QR would own sudo forever.

No inbound firewall holes, phones talk only to the HTTPS origin over WSS.

Wheel parents still type a password. The approval path is only for `omarchy-kids`.

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

`sudo make install` also writes to `/usr`. Prefer the package so systemd sysusers, sudoers, PAM hooks, and the daemon unit are applied.

Then teach coding agents the CLI:

```bash
sudo parentapproval install-skills
```

That symlinks the skill into the parent’s and kids’ agent dirs (`~/.agents/skills`, `~/.claude/skills`, `~/.codex/skills`, `~/.pi/agent/skills`, `~/.gemini/config/skills`, and `~/.grok/skills`). `setup-kid` does the same for the kid.

Then, as the parent (your wheel account, not the kid):

```bash
sudo parentapproval pair          # scan; keys land in /var/lib via the systemd daemon
sudo parentapproval setup-kid milo
```

The package install applies PAM, sudoers, the `omarchy-kids` group, and the daemon. `ask`, `pending`, and `status` talk to the systemd daemon as a regular user. Pair, revoke, doctor, disable, setup-kid, and install-skills need sudo. Use `--dev` only for an unprivileged local dry-run of the daemon.

Optional desktop overlay, so polkit and GUI prompts get the same QR card:

```bash
omarchy plugin add "$PWD/overlay"
# or copy overlay/ to ~/.config/omarchy/plugins/parentapproval/
```

`setup-kid` creates the account if it does not exist. That password is for login and the lock screen. It will not sudo. You keep your own account; that is the emergency fallback when the phone is dead. It also links the agent skill into that kid's home so their coding agents load it without a separate `install-skills`.

## Relay

Default origin: **https://parentapprovals.com**. Self-hosters set:

- Laptop: `OMARCHY_PARENTAPPROVAL_RELAY` or `parentapproval daemon --relay URL`
- Relay process: `RELAY_PUBLIC_URL` (or `PUBLIC_URL`) and `RELAY_DATA` (default `/data`)

`--relay=off` is local-only HTTP (`--dev`). Production does not open a LAN listen port.

See [`deploy/relay/README.md`](deploy/relay/README.md) for Railway and optional Caddy compose. Do not terminate TLS in the relay container.

## Try it without a kid account

Unprivileged (`--dev` is local HTTP, no PAM):

```bash
parentapproval daemon --dev      # terminal 1
sudo parentapproval pair --dev   # terminal 2, scan
parentapproval ask --dev --cmd "pacman -S cowsay"
```

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
| `sudo parentapproval setup-kid NAME` | Create/lock a kid user |
| `sudo parentapproval disable` | Remove PAM hooks without uninstalling |
| `parentapproval status` | Host id, relay, paired phones |
| `sudo parentapproval revoke DEVICE_ID` | Drop a phone |
| `sudo parentapproval doctor` | Check PAM order, daemon, relay |
| `sudo parentapproval install-skills` | Symlink the agent skill (parent + all kids) |
| `parentapproval daemon [--dev] [--relay URL]` | The service |

`parentapproval --help` is the flag-level source of truth.

## Releases

[SemVer 2.0](https://semver.org/) tags (`vMAJOR.MINOR.PATCH`). Linux **amd64** and **arm64** only.

```bash
./scripts/stamp-version v1.2.3
git add VERSION PKGBUILD
git commit -m "Release v1.2.3"
git tag -a v1.2.3 -m "v1.2.3"
git push origin HEAD v1.2.3
```

GoReleaser runs `scripts/stamp-version` from the tag and publishes the binaries. Dry-run: `make release-snapshot`.

## What this is not

- Not a login or lock-screen replacement. The kid still unlocks the session with their own password.
- Not Omarchy's 15-minute passwordless sudo. That feature is for agents acting as *you*.
- Not a kid-proof kernel. Once they have a root shell, the game is over, same as any local privilege product.

Phone lock and OS biometrics are the residual control if the kid gets your unlocked phone. Same as Ask to Buy.

## Protocol

Ed25519 over canonical bytes, not JSON. Specified in [`docs/SPEC.md`](docs/SPEC.md). Wire prefix `OMARCHY-APPROVE/1` is frozen so already-paired phones keep working.
