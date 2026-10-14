SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/dvmrry/akamai-prolexic/internal/version.version=$(VERSION) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.commit=$(COMMIT) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.date=$(DATE)

.PHONY: build install fmt-check vet test race schemas secret-scan check

build:
	go build -ldflags '$(LDFLAGS)' -o bin/prolexic ./cmd/prolexic

# Into $(go env GOPATH)/bin (~/go/bin, on PATH via the dotfiles).
install:
	go install -ldflags '$(LDFLAGS)' ./cmd/prolexic

fmt-check:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

# Regenerate schemas/ from the Go document types (TestSchemas checks them).
schemas:
	go test ./internal/cli -run TestSchemas -update

# The whole working tree, with the repo's rules (EdgeGrid tokens included).
secret-scan:
	gitleaks dir --no-banner --config .gitleaks.toml .

check: fmt-check vet test secret-scan
