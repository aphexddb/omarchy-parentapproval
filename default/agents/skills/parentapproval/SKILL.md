---
name: parentapproval
description: >
  REQUIRED when Omarchy needs parent permission. Kids in omarchy-kids have
  no sudo password — privileged work (sudo, pkexec, polkit, pacman,
  omarchy pkg, systemctl) is approved on a paired parent phone via
  parentapproval. Also use when pairing a phone, setting up a kid,
  testing an approval, or debugging kids sudo. Call this CLI; do not invent
  a password or wrap sudo. Triggers: parent permission, parent approve,
  kids sudo, omarchy-kids, sudo, pkexec, polkit, pacman, omarchy pkg,
  pair phone, ask --cmd, setup-kid, parentapproval,
  "approve sudo from my phone". Use when the user runs /parentapproval.
---

# Parent Approval (`parentapproval`)

Kids in `omarchy-kids` cannot type a sudo password. PAM asks a **paired
parent phone** to sign the request. Pairing is the security boundary — a kid
opening the URL on their own phone cannot approve it.

Wheel parents still type a password (or use Omarchy passwordless sudo).
The approval path is only for `omarchy-kids`.

## When parent permission is needed

This is the app. Check `id -nG` for `omarchy-kids`.

**Kid session:** run the privileged command as usual (`sudo pacman -S cowsay`,
`pkexec …`, `omarchy pkg add …`). Do not wrap sudo. Do not ask for a password.
PAM calls `parentapproval pam`; the paired phone buzzes; wait. The
Omarchy skill's "type a sudo password / use pkexec because you are an agent"
rule does not apply here.

**Ask from a coding agent** (this is the usual path; it runs the command after
the parent approves):

```bash
parentapproval ask --cmd "pacman -S cowsay"
```

`ask` shows the QR, waits for the phone, then runs `CMD` with `sudo`. A
one-shot grant spends that approval so kids are not prompted a second time.

**Wheel / not in `omarchy-kids`:** password or Omarchy passwordless sudo
for a normal `sudo`. `ask --cmd` still phones a parent, then runs the
command with sudo. Use `setup-kid` to put someone on the parent-phone path.

## Commands

Binary is `/usr/bin/parentapproval` after `makepkg -f -si` or `sudo make install`.

| Intent | Command |
|---|---|
| Ask, then run CMD with sudo | `parentapproval ask --cmd "pacman -S cowsay"` |
| Pair parent phone | `parentapproval pair` |
| Enable PAM + daemon | `sudo parentapproval enable` |
| Create / lock a kid user | `sudo parentapproval setup-kid milo` |
| Status / paired phones | `parentapproval status` |
| List pending request | `parentapproval pending` |
| Drop a phone | `parentapproval revoke DEVICE_ID` |
| Check PAM order + daemon | `parentapproval doctor` |
| Teach this user's coding agents | `parentapproval install-skills` |
| Unprivileged dry-run daemon | `parentapproval daemon --dev` |

`pair`, `ask`, `status`, `pending`, `revoke`, and `doctor` talk to the
systemd socket `/run/parentapproval/pam.sock` as a regular user.
`enable`, `disable`, and `setup-kid` still need sudo.
`--dev` / `OMARCHY_PARENTAPPROVAL_DEV=1` is only for an unprivileged local
daemon (`~/.local/state` + a per-user socket).

## Setup (parent wheel account)

```bash
sudo parentapproval enable
parentapproval pair               # scan, confirm the 6-digit code matches
sudo parentapproval setup-kid milo
parentapproval install-skills     # parent account, not root
```

`setup-kid` links this skill into the kid's agent dirs so their coding agents
pick it up — do not run `install-skills` as the kid. `enable` backfills every
current `omarchy-kids` member. `sudo parentapproval install-skills`
does the parent (`SUDO_USER`) and all kids.

On the phone after pair: Add to Home Screen, open the icon, tap Allow
notifications. Next time the kid needs sudo, the phone buzzes.

`setup-kid` creates the login if needed. That password unlocks the session. It
will not sudo.

## Unprivileged dry-run (no PAM)

```bash
parentapproval daemon --dev          # terminal 1; state in ~/.local/state
parentapproval pair --dev            # terminal 2; scan
parentapproval ask --dev --cmd "pacman -S cowsay"
```

`--dev` does not touch PAM or sudoers. It is local HTTP unless `--relay URL`
is set.

## When sudo does not prompt a parent

1. Caller is not in `omarchy-kids` (wheel parent, or you). Use `ask --cmd`, or
   `setup-kid`, or `sudo -u milo sudo pacman -S cowsay` from a kid session.
2. No paired phone: `parentapproval status` then `pair`.
3. Daemon down: `parentapproval doctor` and `sudo systemctl start parentapprovald`.
4. Relay disconnected: `status` should show the relay URL as connected. Check WAN.
5. Keys paired in `--dev` but kid sudo uses the systemd daemon — re-pair with
   `parentapproval pair` (no `--dev`).

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
  it under `/usr/share/parentapproval/agents/skills/parentapproval/`
  and `setup-kid` / `install-skills` symlink it into `~/.agents/skills`,
  `~/.claude/skills`, `~/.codex/skills`, `~/.pi/agent/skills`,
  `~/.gemini/config/skills`, and `~/.grok/skills`.
