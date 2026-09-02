#!/usr/bin/env bash
# parentapproval public bootstrap (MIT).
#
# Review, then run (preferred):
#   curl -fsSL https://raw.githubusercontent.com/aphexddb/omarchy-parentapproval/main/install.sh -o install.sh
#   less install.sh
#   bash install.sh
#
# Convenience (same file). Trusts GitHub + this commit on main:
#   curl -fsSL https://raw.githubusercontent.com/aphexddb/omarchy-parentapproval/main/install.sh | bash
#
# https://parentapprovals.com/install must be this file byte-for-byte, or an
# HTTP redirect to the raw GitHub URL. Otherwise that domain is a second
# trust root.
#   curl -fsSL https://parentapprovals.com/install | bash
#
# Default PARENTAPPROVAL_REF=main. Pin a SemVer tag with PARENTAPPROVAL_REF=vX.Y.Z.
set -euo pipefail

main() {
  # curl|bash has no stdin TTY; reattach so sudo can prompt. Do not abort if
  # /dev/tty exists but is not a controlling terminal (SSH without -t, CI).
  if [[ ! -t 0 && -r /dev/tty ]]; then
    { exec </dev/tty; } 2>/dev/null || true
  fi

  if (( EUID == 0 )); then
    echo "parentapproval: do not run as root. The installer will ask for sudo later." >&2
    exit 1
  fi

  if ! command -v pacman >/dev/null; then
    echo "parentapproval: Arch Linux or Omarchy required." >&2
    exit 1
  fi

  if ! command -v git >/dev/null || ! command -v makepkg >/dev/null; then
    sudo pacman -Syu --needed --noconfirm git base-devel
  fi

  local repo="${PARENTAPPROVAL_REPO:-https://github.com/aphexddb/omarchy-parentapproval.git}"
  local ref="${PARENTAPPROVAL_REF:-main}"
  local dir="${PARENTAPPROVAL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/parentapproval}"
  local origin

  mkdir -p "$(dirname "$dir")"

  if [[ -e "$dir/.git" ]]; then
    origin=$(git -C "$dir" remote get-url origin)
    if [[ "$origin" != "$repo" && "$origin" != "${repo%.git}" && "$origin" != "${repo}.git" ]]; then
      echo "parentapproval: $dir origin does not match PARENTAPPROVAL_REPO" >&2
      echo "  origin: $origin" >&2
      echo "  repo:   $repo" >&2
      exit 1
    fi
    echo "Updating $dir ($ref)"
    git -C "$dir" fetch --depth=1 origin "$ref"
    git -C "$dir" checkout --force FETCH_HEAD
  elif [[ -e "$dir" ]]; then
    echo "parentapproval: $dir exists and is not a git clone of $repo" >&2
    exit 1
  elif [[ "$ref" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    echo "Cloning $repo (then $ref)"
    git clone --depth=1 "$repo" "$dir"
    git -C "$dir" fetch --depth=1 origin "$ref"
    git -C "$dir" checkout --force FETCH_HEAD
  else
    echo "Cloning $repo ($ref)"
    git clone --depth=1 --branch "$ref" "$repo" "$dir"
  fi

  if [[ ! -f "$dir/scripts/dev-install" ]]; then
    echo "parentapproval: missing regular file $dir/scripts/dev-install" >&2
    exit 1
  fi

  exec bash "$dir/scripts/dev-install" "$@"
}

main "$@"
