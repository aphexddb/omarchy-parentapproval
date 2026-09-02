# Parent Approval

The kid wants Steam. You are in the kitchen. You should not have to walk over, take the keyboard, and type `sudo`.

This is a parent-phone approval gate for [Omarchy](https://omarchy.org/) kids accounts. Pair once. Add the page to your Home Screen. Allow notifications. Next time the kid hits sudo, your phone buzzes, shows the command and a match number, and you approve or deny. The kid never learns a sudo password, and **opening the request on an unpaired phone does nothing** — pairing is the security boundary.

Community extra for Omarchy. Not affiliated with Omarchy, Basecamp, or 37signals.

Agents: load [`default/agents/skills/parentapproval/SKILL.md`](default/agents/skills/parentapproval/SKILL.md) (or run `parentapproval install-skills`). The usual test is:

```bash
parentapproval ask --cmd "pacman -S cowsay"
```

## How it works

1. **You pair once**, sitting at the laptop. Scan the pairing URL (a QR is still printed). The phone generates an Ed25519 key and keeps the private half. The laptop stores only the public half. Both screens show the same 6-digit code so a stranger cannot swap in their own key.
2. **Add to Home Screen, tap Allow notifications.** After that the phone is a parent for this machine.
3. **The kid hits sudo** (or a polkit prompt). They are in the `omarchy-kids` group, so PAM does not accept their login password. The laptop asks the relay to notify paired phones.
4. **Your phone buzzes.** Check the command and the match code, tap Approve. The phone signs the request the daemon already knows. One invocation, then it is spent. Replay is refuse.

The QR / URL is a request, not a capability. TOTP is banned on purpose: a kid who photographs an enrollment QR would own sudo forever.

Phones talk only to the HTTPS origin (`https://parentapprovals.com` by default). The laptop daemon dials that origin outbound over WSS. No inbound firewall holes.

Wheel parents still type a password. The approval path is only for `omarchy-kids`.

## Install

Arch / Omarchy package. Writes to `/usr`. Pacman needs sudo.

```bash
./scripts/dev-install
```

That is `makepkg -f -si --noconfirm` plus the overlay plugin. `-f` so makepkg does not reuse a stale tarball. `./install-omarchy` is the same script.

Tear it down (package, overlay, skill links, daemon state; not kid logins):

```bash
./scripts/dev-uninstall
```

`sudo make install` also writes to `/usr`. Prefer the package so systemd sysusers and the daemon unit are enabled.

Then teach coding agents the CLI (as the parent, not root):

```bash
parentapproval install-skills
```

That symlinks the skill into `~/.agents/skills`, `~/.claude/skills`, `~/.codex/skills`, `~/.pi/agent/skills`, `~/.gemini/config/skills`, and `~/.grok/skills`. `setup-kid` does the same for the kid. `sudo parentapproval install-skills` also links every `omarchy-kids` home.

Then, as the parent (your wheel account, not the kid):

```bash
sudo parentapproval enable
parentapproval pair               # scan; keys land in /var/lib via the systemd daemon
sudo parentapproval setup-kid milo
```

`pair`, `ask`, `status`, `pending`, `revoke`, and `doctor` talk to the systemd daemon even as a regular user. `enable`, `disable`, and `setup-kid` still need sudo. Use `--dev` only for an unprivileged local dry-run.

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
parentapproval pair --dev        # terminal 2, scan
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

`--cmd` is the string shown on the phone. It is not executed.

## Commands

| Command | What it does |
|---|---|
| `parentapproval ask --cmd "…"` | Fire a test request (does not run the command) |
| `parentapproval pair` | Pair a parent phone |
| `parentapproval setup-kid NAME` | Create/lock a kid user |
| `parentapproval enable` / `disable` | PAM, sudoers, systemd |
| `parentapproval status` | Host id, relay, paired phones |
| `parentapproval revoke DEVICE_ID` | Drop a phone |
| `parentapproval doctor` | Check PAM order, daemon, relay |
| `parentapproval install-skills` | Symlink the agent skill into this user's coding-agent dirs (root: parent + all kids) |
| `parentapproval daemon [--dev] [--relay URL]` | The service |

`parentapproval --help` is the flag-level source of truth.

## What this is not

- Not a login or lock-screen replacement. The kid still unlocks the session with their own password.
- Not Omarchy's 15-minute passwordless sudo. That feature is for agents acting as *you*.
- Not a kid-proof kernel. Once they have a root shell, the game is over, same as any local privilege product.

Phone lock and OS biometrics are the residual control if the kid gets your unlocked phone. Same as Ask to Buy.

## Protocol

Ed25519 over canonical bytes, not JSON. Specified in [`docs/SPEC.md`](docs/SPEC.md). Wire prefix `OMARCHY-APPROVE/1` is frozen so already-paired phones keep working.
