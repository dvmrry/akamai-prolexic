SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/dvmrry/prolexic/internal/version.version=$(VERSION) \
	-X github.com/dvmrry/prolexic/internal/version.commit=$(COMMIT) \
	-X github.com/dvmrry/prolexic/internal/version.date=$(DATE)

.PHONY: build fmt-check vet test race secret-scan check

build:
	go build -ldflags '$(LDFLAGS)' -o bin/prolexic ./cmd/prolexic

fmt-check:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

# The whole working tree, with the repo's rules (EdgeGrid tokens included).
secret-scan:
	gitleaks dir --no-banner --config .gitleaks.toml .

check: fmt-check vet test secret-scan
