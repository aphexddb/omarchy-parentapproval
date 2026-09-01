# Agents

Parent-phone approval for Omarchy kids sudo.

Coding agents on Omarchy that need parent permission must load
[`default/agents/skills/omarchy-parentapproval/SKILL.md`](default/agents/skills/omarchy-parentapproval/SKILL.md)
and call `omarchy-parentapproval`. Read that skill before using or changing
the CLI.

```bash
omarchy-parentapproval ask --cmd "pacman -S cowsay"
```
