# Maintainer: parentapproval contributors
pkgname=parentapproval
pkgver=0.1.0
pkgrel=32
pkgdesc="Parent-phone approval for Omarchy kids accounts"
arch=('x86_64' 'aarch64')
url="https://github.com/aphexddb/omarchy-parentapproval"
license=('MIT')
depends=('pam' 'sudo')
makedepends=('go')
optdepends=(
  'imv: fullscreen QR on Wayland when the overlay plugin is not installed'
)
replaces=('omarchy-parentapproval')
conflicts=('omarchy-parentapproval')
install=packaging/parentapproval.install
options=('!debug' '!emptydirs')
# In-tree checkout: no release tarball. Directories cannot be listed in
# source=() (makepkg get_filepath only accepts regular files). prepare()
# snapshots the tree into $srcdir. Go caches stay under $srcdir so a
# build-user makepkg does not fight root-owned caches in $HOME.
source=()
sha256sums=()

_src_files=(
  Makefile go.mod go.sum VERSION LICENSE README.md AGENTS.md install.sh
  cmd internal web packaging default overlay
)

prepare() {
  local f v
  v=$(tr -d '[:space:]' < "$startdir/VERSION")
  if [[ $v != "$pkgver" ]]; then
    echo "PKGBUILD pkgver=$pkgver but VERSION is $v" >&2
    return 1
  fi
  for f in "${_src_files[@]}"; do
    rm -rf "$srcdir/$f"
    cp -a "$startdir/$f" "$srcdir/$f"
  done
}

_go_env() {
  export CGO_ENABLED=0
  export GOCACHE="${GOCACHE:-$srcdir/go-cache}"
  export GOMODCACHE="${GOMODCACHE:-$srcdir/go-mod}"
  export GOPATH="${GOPATH:-$srcdir/gopath}"
  # CGO is off, so do not set -linkmode=external (needs a C compiler).
  export GOFLAGS="${GOFLAGS:--buildmode=pie -trimpath -mod=readonly -modcacherw}"
  mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOPATH"
}

build() {
  _go_env
  make -C "$srcdir" PREFIX=/usr
}

check() {
  _go_env
  make -C "$srcdir" test
}

package() {
  make -C "$srcdir" DESTDIR="$pkgdir" PREFIX=/usr install
}
