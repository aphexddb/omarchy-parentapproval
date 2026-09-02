PREFIX ?= /usr
DESTDIR ?=
BIN := parentapproval
RELAY := parentapproval-relay
VERSION := $(shell cat VERSION)
COMMIT := $(shell git rev-parse HEAD 2>/dev/null || true)
GOFLAGS ?= -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build relay test smoke install uninstall check-root-install check-root-uninstall release-snapshot goreleaser-check

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
	go test ./cmd/... ./internal/... ./web ./smoketest/fakephone

# Docker relay e2e. Skips if docker is missing unless PARENTAPPROVAL_SMOKE=1.
.PHONY: smoke
smoke:
	go test -tags=smoke -count=1 -timeout 3m -shuffle=off ./smoketest

goreleaser-check:
	goreleaser check

release-snapshot:
	goreleaser release --snapshot --clean

install: check-root-install build
	install -Dm755 bin/$(BIN) "$(DESTDIR)$(PREFIX)/bin/$(BIN)"
	rm -f "$(DESTDIR)$(PREFIX)/bin/omarchy-parentapproval"
	install -Dm644 packaging/parentapprovald.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/parentapprovald.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-parentapprovald.service"
	install -Dm644 packaging/parentapproval.sysusers "$(DESTDIR)$(PREFIX)/lib/sysusers.d/parentapproval.conf"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-parentapproval.conf"
	install -d -m 750 "$(DESTDIR)/etc/sudoers.d"
	install -m 440 packaging/omarchy-kids.sudoers "$(DESTDIR)/etc/sudoers.d/omarchy-kids"
	install -Dm644 packaging/parentapproval.pam "$(DESTDIR)/etc/pam.d/parentapproval"
	install -Dm644 packaging/parentapproval-polkit.pam "$(DESTDIR)/etc/pam.d/parentapproval-polkit"
	install -Dm644 packaging/50-parentapproval.rules "$(DESTDIR)$(PREFIX)/share/polkit-1/rules.d/50-parentapproval.rules"
	install -Dm644 packaging/parentapproval-polkit.service "$(DESTDIR)$(PREFIX)/lib/systemd/user/parentapproval-polkit.service"
	install -Dm644 LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/parentapproval/LICENSE"
	install -Dm644 README.md "$(DESTDIR)$(PREFIX)/share/doc/parentapproval/README.md"
	install -Dm644 AGENTS.md "$(DESTDIR)$(PREFIX)/share/doc/parentapproval/AGENTS.md"
	install -Dm644 default/agents/skills/parentapproval/SKILL.md "$(DESTDIR)$(PREFIX)/share/parentapproval/agents/skills/parentapproval/SKILL.md"
	install -Dm644 VERSION "$(DESTDIR)$(PREFIX)/share/parentapproval/VERSION"
	install -d "$(DESTDIR)$(PREFIX)/share/parentapproval/overlay"
	install -Dm644 overlay/manifest.json overlay/Panel.qml -t "$(DESTDIR)$(PREFIX)/share/parentapproval/overlay"
	rm -rf "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-parentapproval"
	@if [ -z "$(DESTDIR)" ]; then \
		systemd-sysusers "$(PREFIX)/lib/sysusers.d/parentapproval.conf" >/dev/null 2>&1 || true; \
		"$(PREFIX)/bin/$(BIN)" apply-hooks; \
	fi

uninstall: check-root-uninstall
	@if [ -z "$(DESTDIR)" ] && [ -x "$(PREFIX)/bin/$(BIN)" ]; then \
		"$(PREFIX)/bin/$(BIN)" remove-hooks || true; \
	fi
	rm -f "$(DESTDIR)/etc/sudoers.d/omarchy-kids"
	rm -f "$(DESTDIR)/etc/pam.d/parentapproval"
	rm -f "$(DESTDIR)/etc/pam.d/parentapproval-polkit"
	rm -f "$(DESTDIR)$(PREFIX)/share/polkit-1/rules.d/50-parentapproval.rules"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/user/parentapproval-polkit.service"
	rm -f "$(DESTDIR)$(PREFIX)/bin/$(BIN)" "$(DESTDIR)$(PREFIX)/bin/omarchy-parentapproval"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/parentapprovald.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-parentapprovald.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/parentapproval.conf"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-parentapproval.conf"
	rm -rf "$(DESTDIR)$(PREFIX)/share/parentapproval" "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/parentapproval" "$(DESTDIR)$(PREFIX)/share/doc/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/licenses/parentapproval" "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-parentapproval"
