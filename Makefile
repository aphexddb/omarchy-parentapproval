PREFIX ?= /usr
DESTDIR ?=
VERSION := $(shell cat VERSION)
GOFLAGS ?= -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build relay test install uninstall

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/omarchy-parentapproval ./cmd/omarchy-parentapproval

relay:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/omarchy-parentapproval-relay ./cmd/omarchy-parentapproval-relay

test:
	go test ./cmd/... ./internal/... ./web

install: build
	install -Dm755 bin/omarchy-parentapproval "$(DESTDIR)$(PREFIX)/bin/omarchy-parentapproval"
	install -Dm644 packaging/omarchy-parentapprovald.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-parentapprovald.service"
	install -Dm644 packaging/omarchy-parentapproval.sysusers "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-parentapproval.conf"
	install -Dm644 LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-parentapproval/LICENSE"
	install -Dm644 README.md "$(DESTDIR)$(PREFIX)/share/doc/omarchy-parentapproval/README.md"
	install -Dm644 AGENTS.md "$(DESTDIR)$(PREFIX)/share/doc/omarchy-parentapproval/AGENTS.md"
	install -Dm644 default/agents/skills/omarchy-parentapproval/SKILL.md "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval/agents/skills/omarchy-parentapproval/SKILL.md"
	install -Dm644 VERSION "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval/VERSION"
	install -d "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval/overlay"
	install -Dm644 overlay/manifest.json overlay/Panel.qml overlay/qmldir -t "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval/overlay"
	@if [ -z "$(DESTDIR)" ] && [ "$$(id -u)" != 0 ]; then \
		"$(PREFIX)/bin/omarchy-parentapproval" install-skills || true; \
	fi

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/omarchy-parentapproval"
	rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-parentapprovald.service"
	rm -f "$(DESTDIR)$(PREFIX)/lib/sysusers.d/omarchy-parentapproval.conf"
	rm -rf "$(DESTDIR)$(PREFIX)/share/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/omarchy-parentapproval"
	rm -rf "$(DESTDIR)$(PREFIX)/share/licenses/omarchy-parentapproval"
