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

[SemVer 2.0](https://semver.org/). Tags are `vMAJOR.MINOR.PATCH` (prerelease: `v1.2.3-rc.1`). `VERSION` is the same number without the `v`. `make` and GoReleaser stamp `-X main.version` and `-X main.commit` (`parentapproval version` prints `1.2.3 (short-sha)`). Untagged `go build` falls back to the embedded `VERSION` file and VCS revision.

```bash
./scripts/stamp-version v1.2.3
git add VERSION PKGBUILD
git commit -m "Release v1.2.3"
git tag -a v1.2.3 -m "v1.2.3"
git push origin HEAD v1.2.3
```

`stamp-version` writes `VERSION`, sets the in-tree `PKGBUILD` `pkgver` (Arch-safe: `-`/`+` → `_`), and resets `pkgrel` to 1. That `PKGBUILD` is the source checkout recipe for `./scripts/dev-install`; it is not the AUR package.

GoReleaser publishes Linux amd64 and arm64 archives (CLI payload matches `make install`) and generates `parentapproval-bin` (PKGBUILD + `.SRCINFO`) for AUR. Same-version rebuild of the in-tree package: bump `pkgrel` by hand. Dry-run: `make release-snapshot`.

AUR upload: create `parentapproval-bin` on AUR once, then set repo secret `AUR_KEY` to an unprotected SSH key that can push `ssh://aur@aur.archlinux.org/parentapproval-bin.git`. Missing key or a snapshot/prerelease skips upload; the files still land in `dist/`.
