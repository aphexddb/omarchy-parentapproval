---
name: omarchy-parentapproval
description: >
  Parent-phone approval for Omarchy kids sudo and polkit. Use whenever
  pairing a parent phone, setting up a kid account, testing an approval,
  debugging kids sudo, or running omarchy-parentapproval. Triggers:
  omarchy-parentapproval, parent approve, kids sudo, omarchy-kids, pair
  phone, ask --cmd, setup-kid, parent-phone approval, "approve sudo from
  my phone". Use when the user runs /omarchy-parentapproval.
---

# Parent Approval (`omarchy-parentapproval`)

Kids in `omarchy-kids` cannot type a sudo password. PAM asks a **paired
parent phone** to sign the request. Pairing is the security boundary — a kid
opening the URL on their own phone cannot approve it.

Wheel parents still type a password. The approval path is only for `omarchy-kids`.

## Reach for this first

Test without a kid account (phone already paired to this daemon):

```bash
omarchy-parentapproval ask --cmd "pacman -S cowsay"
```

That mints a live request, prints a QR of the approval URL, and waits. It does
**not** run pacman. Swap the `--cmd` string for whatever the parent should see.

Kid session (after `setup-kid`): they run `sudo pacman -S cowsay` as usual.
The paired phone buzzes. Do not wrap sudo.

## Commands

Prefer the binary on `PATH`. After `make PREFIX="$HOME/.local" install`,
root cannot see it — use `sudo ~/.local/bin/omarchy-parentapproval …`.

| Intent | Command |
|---|---|
| Test request (no kid) | `omarchy-parentapproval ask --cmd "pacman -S cowsay"` |
| Pair parent phone | `omarchy-parentapproval pair` |
| Enable PAM + daemon | `sudo omarchy-parentapproval enable` |
| Create / lock a kid user | `sudo omarchy-parentapproval setup-kid milo` |
| Status / paired phones | `omarchy-parentapproval status` |
| Drop a phone | `omarchy-parentapproval revoke DEVICE_ID` |
| Check PAM order + daemon | `omarchy-parentapproval doctor` |
| Teach coding agents this skill | `omarchy-parentapproval install-skills` |
| Unprivileged dry-run daemon | `omarchy-parentapproval daemon --dev` |

`pair`, `ask`, `status`, `pending`, `revoke`, and `doctor` talk to the
systemd socket `/run/omarchy-parentapproval/pam.sock` as a regular user.
`enable`, `disable`, and `setup-kid` still need sudo.
`--dev` / `OMARCHY_PARENTAPPROVAL_DEV=1` is only for an unprivileged local
daemon (`~/.local/state` + a per-user socket).

## Setup (parent wheel account)

```bash
sudo omarchy-parentapproval enable
omarchy-parentapproval pair               # scan, confirm the 6-digit code matches
sudo omarchy-parentapproval setup-kid milo
omarchy-parentapproval install-skills     # as the parent, not root
```

On the phone after pair: Add to Home Screen, open the icon, tap Allow
notifications. Next time the kid needs sudo, the phone buzzes.

`setup-kid` creates the login if needed. That password unlocks the session. It
will not sudo.

## Unprivileged dry-run (no PAM)

```bash
omarchy-parentapproval daemon --dev          # terminal 1; state in ~/.local/state
omarchy-parentapproval pair --dev            # terminal 2; scan
omarchy-parentapproval ask --dev --cmd "pacman -S cowsay"
```

`--dev` does not touch PAM or sudoers. It is local HTTP unless `--relay URL`
is set.

## When sudo does not prompt a parent

1. Caller is not in `omarchy-kids` (wheel parent, or you). Use `ask --cmd`, or
   `setup-kid`, or `sudo -u milo sudo pacman -S cowsay` from a kid session.
2. No paired phone: `omarchy-parentapproval status` then `pair`.
3. Daemon down: `omarchy-parentapproval doctor` and `sudo systemctl start omarchy-parentapprovald`.
4. Relay disconnected: `status` should show the relay URL as connected. Check WAN.
5. Keys paired in `--dev` but kid sudo uses the systemd daemon — re-pair with
   `omarchy-parentapproval pair` (no `--dev`).

## Relay

Default HTTPS origin: **https://parentapprovals.com**. The laptop dials it
outbound over WSS. The phone never talks to the laptop. Self-hosters set
`OMARCHY_PARENTAPPROVAL_RELAY` on the laptop and `RELAY_PUBLIC_URL` on the
relay. `--relay=off` is local-only.

There is no firewall / ufw / LAN listen port in production.

## Do not

- Do not put the kid in `wheel`.
- Do not share the parent's sudo password with the kid.
- Do not treat the QR as a capability; it is a request the paired key must sign.
- Do not edit `/usr/share/omarchy/` to "install" this skill. This package ships
  it under `/usr/share/omarchy-parentapproval/agents/skills/omarchy-parentapproval/`
  and `install-skills` symlinks it into `~/.agents/skills`, `~/.claude/skills`,
  `~/.codex/skills`, `~/.pi/agent/skills`, `~/.gemini/config/skills`, and
  `~/.grok/skills`.
