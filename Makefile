SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -X github.com/dvmrry/akamai-prolexic/internal/version.version=$(VERSION) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.commit=$(COMMIT) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.date=$(DATE)

.PHONY: build install fmt-check vet tidy-check test race cross dist version-check vuln actionlint lint fuzz schemas docs secret-scan secret-scan-commits check

build:
	go build -ldflags '$(LDFLAGS)' -o bin/prolexic ./cmd/prolexic

# Into $(go env GOPATH)/bin (~/go/bin, on PATH via the dotfiles).
install:
	go install -ldflags '$(LDFLAGS)' ./cmd/prolexic

fmt-check:
	@files="$$(find . -path ./.claude -prune -o -name '*.go' -print | xargs gofmt -l)"; if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

vet:
	go vet ./...

# go.mod and go.sum match the code (a hand edit or an update can leave them
# out of step).
tidy-check:
	go mod tidy -diff

test:
	go test ./...

race:
	go test -race ./...

# Builds every release platform without cgo: static binaries, and a
# cross-compile that works from any host (a nix shell turns cgo on).
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
cross:
	@for p in $(PLATFORMS); do \
		echo "== $$p"; CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go build -o /dev/null ./cmd/prolexic; \
	done

# The release binaries of VERSION into dist/, with SHA256SUMS. The release
# workflow runs it on main; -trimpath and the commit date as the build date
# make a rebuild from the same commit identical.
dist: VERSION = v$(shell cat VERSION)
dist: DATE = $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)
dist:
	rm -rf dist && mkdir dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; if [ "$$os" = windows ]; then ext=.exe; fi; \
		echo "== $$p"; CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o "dist/prolexic_$$(cat VERSION)_$${os}_$${arch}$$ext" ./cmd/prolexic; \
	done
	cd dist && shasum -a 256 prolexic_* > SHA256SUMS

# Every pull request to main raises VERSION, and merging it releases
# v<VERSION> (.github/workflows/release.yml). This fails when VERSION is
# already tagged or below the newest tag; CI runs it on each pull request.
version-check:
	go run ./internal/tools/releasever check

# Known vulnerabilities in code we reach, standard library included. It
# needs the network and its answer changes over time, so check leaves it out;
# CI runs it on every pull request and weekly.
GOVULNCHECK_VERSION := v1.9.0
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

ACTIONLINT_VERSION := v1.7.12
actionlint:
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

# .golangci.yml holds the settings.
GOLANGCI_LINT_VERSION := v2.14.0
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

# Fuzz each target for FUZZTIME (go test runs only one -fuzz target at a
# time). make check replays only the seed inputs; run this now and then.
FUZZTIME ?= 30s
fuzz:
	@for t in FuzzEntry FuzzDesiredFile FuzzEntriesHash FuzzPlanDiff; do \
		echo "== $$t"; go test ./internal/ncf -run '^$$' -fuzz "^$$t\$$" -fuzztime $(FUZZTIME); \
	done

# Regenerate schemas/ from the Go document types (TestSchemas checks them).
schemas:
	go test ./internal/cli -run TestSchemas -update

# Regenerate docs/cli/ (the Markdown CLI reference) from the command tree
# (TestDocsCurrent checks it).
docs:
	go run ./internal/tools/gendocs docs/cli

# The whole working tree, with the repo's rules (EdgeGrid tokens included).
secret-scan:
	gitleaks dir --no-banner --config .gitleaks.toml .

# The commits of RANGE (base..head): a secret added and removed again within
# a pull request is gone from the tree but still in its commits. CI scans
# each pull request's.
secret-scan-commits:
	gitleaks git --no-banner --config .gitleaks.toml --log-opts='$(RANGE)' .

check: fmt-check vet tidy-check test secret-scan
