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

[SemVer 2.0](https://semver.org/). Tags are `vMAJOR.MINOR.PATCH` (prerelease: `v1.2.3-rc.1`). `VERSION` is the same number without the `v`. The CLI embeds `VERSION`; `make` and GoReleaser also stamp `-X main.version` from `VERSION` / the tag.

```bash
./scripts/stamp-version v1.2.3
git add VERSION PKGBUILD
git commit -m "Release v1.2.3"
git tag -a v1.2.3 -m "v1.2.3"
git push origin HEAD v1.2.3
```

`stamp-version` writes `VERSION`, sets `PKGBUILD` `pkgver` (Arch-safe: `-`/`+` → `_`), and resets `pkgrel` to 1. GoReleaser runs the same script from the tag, then publishes Linux amd64 and arm64 only. Same-version rebuild: bump `pkgrel` by hand. Dry-run: `make release-snapshot`.
