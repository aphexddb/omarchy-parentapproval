PREFIX ?= /usr
DESTDIR ?=
VERSION := $(shell cat VERSION)
GOFLAGS ?= -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test install uninstall

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/omarchy-qr-sudo ./cmd/omarchy-qr-sudo

test:
	go test ./cmd/... ./internal/... ./web

install: build
	install -Dm755 bin/omarchy-qr-sudo "$(DESTDIR)$(PREFIX)/bin/omarchy-qr-sudo"
	install -Dm644 packaging/omarchy-qr-sudod.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-qr-sudod.service"
	install -Dm644 packaging/omarchy-qr-sudo.sysusers "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-qr-sudo.conf"
	install -Dm644 LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-qr-sudo/LICENSE"
	install -Dm644 README.md "$(DESTDIR)$(PREFIX)/share/doc/omarchy-qr-sudo/README.md"
	install -Dm644 VERSION "$(DESTDIR)$(PREFIX)/share/omarchy-qr-sudo/VERSION"
	install -d "$(DESTDIR)$(PREFIX)/share/omarchy-qr-sudo/overlay"
	install -Dm644 overlay/manifest.json overlay/Panel.qml overlay/qmldir -t "$(DESTDIR)$(PREFIX)/share/omarchy-qr-sudo/overlay"

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/omarchy-qr-sudo"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-qr-sudod.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-qr-sudo.conf"
	rm -rf "$(DESTDIR)$(PREFIX)/share/omarchy-qr-sudo"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/omarchy-qr-sudo"
	rm -rf "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-qr-sudo"
