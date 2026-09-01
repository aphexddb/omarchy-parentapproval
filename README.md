# Parent Approval

The kid wants Steam. You are in the kitchen. You should not have to walk over, take the keyboard, and type `sudo`.

This is a parent-phone approval gate for [Omarchy](https://omarchy.org/) kids accounts. Pair once. Add the page to your Home Screen. Allow notifications. Next time the kid hits sudo, your phone buzzes, shows the command and a match number, and you approve or deny. The kid never learns a sudo password, and **opening the request on an unpaired phone does nothing** — pairing is the security boundary.

Community extra for Omarchy. Not affiliated with Omarchy, Basecamp, or 37signals.

Agents: load [`default/agents/skills/omarchy-parentapproval/SKILL.md`](default/agents/skills/omarchy-parentapproval/SKILL.md) (or run `omarchy-parentapproval install-skills`). The usual test is:

```bash
omarchy-parentapproval ask --cmd "pacman -S cowsay"
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

```bash
make PREFIX="$HOME/.local" install
# or rebuild the Arch package ( -f so makepkg does not reuse a stale tarball )
makepkg -f -si
```

Then teach coding agents the CLI (as the parent, not root):

```bash
omarchy-parentapproval install-skills
```

That symlinks the skill into `~/.agents/skills`, `~/.claude/skills`, `~/.codex/skills`, `~/.pi/agent/skills`, `~/.gemini/config/skills`, and `~/.grok/skills`.

Then, as the parent (your wheel account, not the kid). After `makepkg -si` the binary is on root's PATH (`/usr/bin`):

```bash
sudo omarchy-parentapproval enable
omarchy-parentapproval pair               # scan; keys land in /var/lib via the systemd daemon
sudo omarchy-parentapproval setup-kid milo
```

`pair`, `ask`, `status`, `pending`, `revoke`, and `doctor` talk to the systemd daemon even as a regular user. `enable`, `disable`, and `setup-kid` still need sudo. Use `--dev` only for an unprivileged local dry-run.

`~/.local/bin` is not on root's PATH. If you installed with `make PREFIX="$HOME/.local" install` (or `./install-omarchy`), call privileged commands with the absolute path:

```bash
sudo ~/.local/bin/omarchy-parentapproval enable
~/.local/bin/omarchy-parentapproval pair
sudo ~/.local/bin/omarchy-parentapproval setup-kid milo
```

Optional desktop overlay, so polkit and GUI prompts get the same QR card:

```bash
omarchy plugin add "$PWD/overlay"
# or copy overlay/ to ~/.config/omarchy/plugins/parent.approve/
```

`setup-kid` creates the account if it does not exist. That password is for login and the lock screen. It will not sudo. You keep your own account; that is the emergency fallback when the phone is dead.

## Relay

Default origin: **https://parentapprovals.com**. Self-hosters set:

- Laptop: `OMARCHY_PARENTAPPROVAL_RELAY` or `omarchy-parentapproval daemon --relay URL`
- Relay process: `RELAY_PUBLIC_URL` (or `PUBLIC_URL`) and `RELAY_DATA` (default `/data`)

`--relay=off` is local-only HTTP (`--dev`). Production does not open a LAN listen port.

See [`deploy/relay/README.md`](deploy/relay/README.md) for Railway and optional Caddy compose. Do not terminate TLS in the relay container.

## Try it without a kid account

Unprivileged (`--dev` is local HTTP, no PAM):

```bash
omarchy-parentapproval daemon --dev      # terminal 1
omarchy-parentapproval pair --dev        # terminal 2, scan
omarchy-parentapproval ask --dev --cmd "pacman -S cowsay"
```

Against a local relay:

```bash
make relay
PORT=8080 RELAY_PUBLIC_URL=http://127.0.0.1:8080 RELAY_DATA=/tmp/parentapproval-data \
  ./bin/omarchy-parentapproval-relay
omarchy-parentapproval daemon --dev --relay http://127.0.0.1:8080
```

Against the installed systemd daemon (phone already paired):

```bash
omarchy-parentapproval ask --cmd "pacman -S cowsay"
```

`--cmd` is the string shown on the phone. It is not executed.

## Commands

| Command | What it does |
|---|---|
| `omarchy-parentapproval ask --cmd "…"` | Fire a test request (does not run the command) |
| `omarchy-parentapproval pair` | Pair a parent phone |
| `omarchy-parentapproval setup-kid NAME` | Create/lock a kid user |
| `omarchy-parentapproval enable` / `disable` | PAM, sudoers, systemd |
| `omarchy-parentapproval status` | Host id, relay, paired phones |
| `omarchy-parentapproval revoke DEVICE_ID` | Drop a phone |
| `omarchy-parentapproval doctor` | Check PAM order, daemon, relay |
| `omarchy-parentapproval install-skills` | Symlink the agent skill into coding-agent skill dirs |
| `omarchy-parentapproval daemon [--dev] [--relay URL]` | The service |

`omarchy-parentapproval --help` is the flag-level source of truth.

## What this is not

- Not a login or lock-screen replacement. The kid still unlocks the session with their own password.
- Not Omarchy's 15-minute passwordless sudo. That feature is for agents acting as *you*.
- Not a kid-proof kernel. Once they have a root shell, the game is over, same as any local privilege product.

Phone lock and OS biometrics are the residual control if the kid gets your unlocked phone. Same as Ask to Buy.

## Protocol

Ed25519 over canonical bytes, not JSON. Specified in [`docs/SPEC.md`](docs/SPEC.md). Wire prefix `OMARCHY-APPROVE/1` is frozen so already-paired phones keep working.
