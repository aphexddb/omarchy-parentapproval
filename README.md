# Parent Approve

The kid wants Steam. You are in the kitchen. You should not have to walk over, take the keyboard, and type `sudo`.

This is a parent-phone approval gate for [Omarchy](https://omarchy.org/) kids accounts. The laptop shows a QR code. You scan it. Your phone shows the command and a match number. Approve or deny. The kid never learns a sudo password, and **scanning the QR with their own phone does nothing** — pairing is the security boundary, not the camera.

Community extra for Omarchy. Not affiliated with Omarchy, Basecamp, or 37signals.

## How it works

1. **You pair once**, sitting at the laptop. The phone generates an Ed25519 key and keeps the private half. The laptop stores only the public half. Both screens show the same 6-digit code so a guest on the Wi-Fi cannot swap in their own key.
2. **The kid hits sudo** (or a polkit prompt). They are in the `omarchy-kids` group, so PAM does not accept their login password. A QR goes on the TTY, and on the desktop if the overlay plugin is installed.
3. **You scan, check the command and the match code, tap Approve.** The phone signs the request the daemon already knows. One invocation, then it is spent. Replay is refuse.

The QR is a request, not a capability. TOTP is banned on purpose: a kid who photographs an enrollment QR would own sudo forever.

Same Wi-Fi is the assumption. Nothing phones home. Port 7421 opens on RFC1918 only while a pairing session or an approval is live, then it closes.

## Install

```bash
make PREFIX="$HOME/.local" install
# or rebuild the Arch package ( -f so makepkg does not reuse a stale tarball )
makepkg -f -si
```

Omarchy's firewall denies all incoming, including ping. Do not test with ping. From another device, while `pair` is waiting:

```bash
curl -v --max-time 3 http://<laptop-lan-ip>:7421/
```

`pair` prints `listen` and `firewall`. If those lines are missing, you are still running an old binary.

Then, as the parent (your wheel account, not the kid). After `makepkg -si` the binary is on root's PATH (`/usr/bin`):

```bash
sudo omarchy-qr-sudo enable
omarchy-qr-sudo pair          # scan with your phone, confirm the code on the laptop
sudo omarchy-qr-sudo setup-kid milo
```

`~/.local/bin` is not on root's PATH. If you installed with `make PREFIX="$HOME/.local" install` (or `./install-omarchy`), call `enable` and `setup-kid` with the absolute path:

```bash
sudo ~/.local/bin/omarchy-qr-sudo enable
~/.local/bin/omarchy-qr-sudo pair
sudo ~/.local/bin/omarchy-qr-sudo setup-kid milo
```

Optional desktop overlay, so polkit and GUI prompts get the same QR card:

```bash
omarchy plugin add "$PWD/overlay"
# or copy overlay/ to ~/.config/omarchy/plugins/parent.approve/
```

`setup-kid` creates the account if it does not exist. That password is for login and the lock screen. It will not sudo. You keep your own account; that is the emergency fallback when the phone is dead.

## Try it without a kid account

```bash
omarchy-qr-sudo daemon --dev      # terminal 1
omarchy-qr-sudo pair              # terminal 2, scan
omarchy-qr-sudo ask --cmd "pacman -S steam"
```

`--dev` keeps state in `~/.local/state/omarchy-qr-sudo` and does not touch PAM.

## Commands

| Command | What it does |
|---|---|
| `omarchy-qr-sudo pair` | Pair a parent phone |
| `omarchy-qr-sudo ask --cmd "…"` | Fire a test request |
| `omarchy-qr-sudo setup-kid NAME` | Create/lock a kid user |
| `omarchy-qr-sudo enable` / `disable` | PAM, sudoers, systemd |
| `omarchy-qr-sudo status` | Host id and paired phones |
| `omarchy-qr-sudo revoke DEVICE_ID` | Drop a phone |
| `omarchy-qr-sudo doctor` | Check PAM order and the daemon |
| `omarchy-qr-sudo daemon [--dev]` | The service |

## What this is not

- Not a login or lock-screen replacement. The kid still unlocks the session with their own password.
- Not Omarchy's 15-minute passwordless sudo. That feature is for agents acting as *you*.
- Not Family Link in the cloud. If you are off the home LAN, the URL in the QR is dead on purpose.
- Not a kid-proof kernel. Once they have a root shell, the game is over, same as any local privilege product.

Phone lock and OS biometrics are the residual control if the kid gets your unlocked phone. Same as Ask to Buy.

## Protocol

Ed25519 over canonical bytes, not JSON. Specified in [`docs/SPEC.md`](docs/SPEC.md).
