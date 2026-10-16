SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/dvmrry/akamai-prolexic/internal/version.version=$(VERSION) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.commit=$(COMMIT) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.date=$(DATE)

.PHONY: build install fmt-check vet test race cross vuln actionlint fuzz schemas docs secret-scan check

build:
	go build -ldflags '$(LDFLAGS)' -o bin/prolexic ./cmd/prolexic

# Into $(go env GOPATH)/bin (~/go/bin, on PATH via the dotfiles).
install:
	go install -ldflags '$(LDFLAGS)' ./cmd/prolexic

fmt-check:
	@files="$$(find . -path ./.claude -prune -o -name '*.go' -print | xargs gofmt -l)"; if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

vet:
	go vet ./...

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

# Known vulnerabilities in code we reach, standard library included. It
# needs the network and its answer changes over time, so check leaves it out;
# CI runs it on every pull request and weekly.
GOVULNCHECK_VERSION := v1.9.0
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

ACTIONLINT_VERSION := v1.7.12
actionlint:
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

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

check: fmt-check vet test secret-scan
