# Maintainer: omarchy-qr-sudo contributors
pkgname=omarchy-qr-sudo
pkgver=0.1.0
pkgrel=13
pkgdesc="Parent-phone QR approval for Omarchy kids accounts"
arch=('x86_64' 'aarch64')
url="https://github.com/gardiner/omarchy-qr-sudo"
license=('MIT')
depends=('pam' 'sudo')
makedepends=('go')
optdepends=(
  'imv: fullscreen QR on Wayland when the overlay plugin is not installed'
  'ufw: opens port 7421 on the LAN only while a request is live'
)
install=packaging/omarchy-qr-sudo.install
options=('!debug' '!emptydirs')
source=()
sha256sums=()

# In-tree flying-toasters build: compile from $startdir. Go caches live under
# $srcdir so makepkg as the build user does not fight root-owned cache dirs.
# Tests must not use ./... — pkg/ and src/ are packaging dirs, not Go packages.
_go_env() {
  export GOCACHE="${GOCACHE:-$srcdir/go-cache}"
  export GOMODCACHE="${GOMODCACHE:-$srcdir/go-mod}"
  export GOPATH="${GOPATH:-$srcdir/gopath}"
  export GOFLAGS="${GOFLAGS:--trimpath -modcacherw}"
  mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOPATH"
}

build() {
  _go_env
  make -C "$startdir" PREFIX=/usr
}

check() {
  _go_env
  make -C "$startdir" test
}

package() {
  make -C "$startdir" DESTDIR="$pkgdir" PREFIX=/usr install
}
