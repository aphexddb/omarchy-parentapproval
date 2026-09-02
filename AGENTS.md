# Agents

Parent-phone approval for Omarchy kids sudo.

Coding agents on Omarchy that need parent permission must load
[`default/agents/skills/parentapproval/SKILL.md`](default/agents/skills/parentapproval/SKILL.md)
and call `parentapproval`. Read that skill before using or changing
the CLI.

```bash
parentapproval ask --cmd "pacman -S cowsay"
```

## Release

Bump the same version in `VERSION` and `PKGBUILD` (`pkgver`; reset `pkgrel` to 1). The CLI reads `VERSION` on `go build`; `make` and GoReleaser stamp it via `-X main.version`. Commit, then tag and push — Linux amd64 and arm64 binaries only.

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Dry-run (no GitHub upload): `make release-snapshot`.
