# Agents

Parent-phone approval for Omarchy kids sudo.

Coding agents on Omarchy that need parent permission must load
[`default/agents/skills/parentapproval/SKILL.md`](default/agents/skills/parentapproval/SKILL.md)
and call `parentapproval`. Read that skill before using or changing
the CLI.

```bash
parentapproval ask --cmd "pacman -S cowsay"
```
