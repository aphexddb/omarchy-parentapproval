PREFIX ?= /usr
DESTDIR ?=
BIN := parentapproval
RELAY := parentapproval-relay
VERSION := $(shell cat VERSION)
GOFLAGS ?= -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build relay test install uninstall check-root-install check-root-uninstall

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/parentapproval
	rm -f bin/omarchy-parentapproval

# DESTDIR is for makepkg/fakeroot. A live install writes to PREFIX (/usr) and needs root.
define require_root
	@if [ -z "$(DESTDIR)" ] && [ "$$(id -u)" != 0 ]; then \
		echo "$(1) requires root. Use: sudo make $(1)   or   makepkg -f -si" >&2; \
		exit 1; \
	fi
endef

check-root-install:
	$(call require_root,install)

check-root-uninstall:
	$(call require_root,uninstall)

relay:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(RELAY) ./cmd/parentapproval-relay
	rm -f bin/omarchy-parentapproval-relay

test:
	go test ./cmd/... ./internal/... ./web

install: check-root-install build
	install -Dm755 bin/$(BIN) "$(DESTDIR)$(PREFIX)/bin/$(BIN)"
	rm -f "$(DESTDIR)$(PREFIX)/bin/omarchy-parentapproval"
	install -Dm644 packaging/parentapprovald.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/parentapprovald.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-parentapprovald.service"
	install -Dm644 packaging/parentapproval.sysusers "$(DESTDIR)$(PREFIX)/lib/sysusers.d/parentapproval.conf"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-parentapproval.conf"
	install -Dm644 LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/parentapproval/LICENSE"
	install -Dm644 README.md "$(DESTDIR)$(PREFIX)/share/doc/parentapproval/README.md"
	install -Dm644 AGENTS.md "$(DESTDIR)$(PREFIX)/share/doc/parentapproval/AGENTS.md"
	install -Dm644 default/agents/skills/parentapproval/SKILL.md "$(DESTDIR)$(PREFIX)/share/parentapproval/agents/skills/parentapproval/SKILL.md"
	install -Dm644 VERSION "$(DESTDIR)$(PREFIX)/share/parentapproval/VERSION"
	install -d "$(DESTDIR)$(PREFIX)/share/parentapproval/overlay"
	install -Dm644 overlay/manifest.json overlay/Panel.qml overlay/qmldir -t "$(DESTDIR)$(PREFIX)/share/parentapproval/overlay"
	rm -rf "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-parentapproval"

uninstall: check-root-uninstall
	rm -f "$(DESTDIR)$(PREFIX)/bin/$(BIN)" "$(DESTDIR)$(PREFIX)/bin/omarchy-parentapproval"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/parentapprovald.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-parentapprovald.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/parentapproval.conf"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-parentapproval.conf"
	rm -rf "$(DESTDIR)$(PREFIX)/share/parentapproval" "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/parentapproval" "$(DESTDIR)$(PREFIX)/share/doc/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/licenses/parentapproval" "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-parentapproval"
