SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -X github.com/dvmrry/akamai-prolexic/internal/version.version=$(VERSION) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.commit=$(COMMIT) \
	-X github.com/dvmrry/akamai-prolexic/internal/version.date=$(DATE)

.PHONY: build install fmt-check vet tidy-check test race cross dist release-version vuln actionlint lint deadcode licenses install-gitleaks fuzz schemas docs secret-scan secret-scan-commits check

build:
	go build -ldflags '$(LDFLAGS)' -o bin/prolexic ./cmd/prolexic

# Into $(go env GOPATH)/bin (~/go/bin, on PATH via the dotfiles).
install:
	go install -ldflags '$(LDFLAGS)' ./cmd/prolexic

fmt-check:
	@files="$$(find . -path ./.claude -prune -o -name '*.go' -print | xargs gofmt -l)"; if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

vet:
	go vet ./...

# The module cache matches go.sum, and go.mod and go.sum match the code (a
# hand edit or an update can leave them out of step).
tidy-check:
	go mod verify
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

# The release files of VERSION (make dist VERSION=v0.1.0) into dist/: for each
# platform an archive (the binary, the licence, the docs) and its SBOM, then
# SHA256SUMS over them. CI builds it on every pull request and the release
# workflow publishes it. -trimpath and the commit date as the build date make a
# rebuild of a binary from the same commit identical.
# renovate: datasource=go depName=github.com/CycloneDX/cyclonedx-gomod
CYCLONEDX_VERSION := v1.12.0
dist: DATE = $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)
dist:
	rm -rf dist && mkdir dist
	@tools="$$(mktemp -d)"; trap 'rm -rf "$$tools"' EXIT; \
	GOBIN="$$tools" go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_VERSION); \
	version='$(VERSION)'; \
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; if [ "$$os" = windows ]; then ext=.exe; fi; \
		name="prolexic_$${version#v}_$${os}_$${arch}"; dir="dist/$$name"; \
		echo "== $$p"; mkdir -p "$$dir/docs"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o "$$dir/prolexic$$ext" ./cmd/prolexic; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch "$$tools/cyclonedx-gomod" app -json -licenses -main cmd/prolexic -output "dist/$$name.sbom.cdx.json" .; \
		cp LICENSE README.md "$$dir/"; \
		cp docs/design.md docs/runbook.md "$$dir/docs/"; \
		cp -R docs/cli "$$dir/docs/cli"; \
		cp -R schemas "$$dir/schemas"; \
		tar -C dist -czf "dist/$$name.tar.gz" "$$name"; \
		rm -rf "$$dir"; \
	done
	cd dist && shasum -a 256 *.tar.gz *.sbom.cdx.json > SHA256SUMS

# What this branch would release: the docs/releases/vX.Y.Z.md it adds, or none.
# It fails on notes that are edited, empty or not the next version. A pull
# request needs either notes or the no-release label (release-notes.yml).
RELEASE_BASE ?= origin/main
release-version:
	go run ./internal/tools/releasever $(RELEASE_BASE) HEAD

# Known vulnerabilities in code we reach, standard library included. It
# needs the network and its answer changes over time, so check leaves it out;
# CI runs it on every pull request and weekly.
# renovate: datasource=go depName=golang.org/x/vuln
GOVULNCHECK_VERSION := v1.9.0
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# renovate: datasource=go depName=github.com/rhysd/actionlint
ACTIONLINT_VERSION := v1.7.12
actionlint:
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

# .golangci.yml holds the settings.
# renovate: datasource=go depName=github.com/golangci/golangci-lint/v2
GOLANGCI_LINT_VERSION := v2.15.0
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

# Fails on a function nothing reaches, tests included. There are no build-tagged
# files, so one platform's answer covers them all.
# renovate: datasource=go depName=golang.org/x/tools
DEADCODE_VERSION := v0.52.0
deadcode:
	@out="$$(go run golang.org/x/tools/cmd/deadcode@$(DEADCODE_VERSION) -test ./...)"; \
	if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

# Every dependency compiled into the binary is under a licence the release can
# ship. prolexic's own licence is its own business, so it is ignored here.
# renovate: datasource=go depName=github.com/google/go-licenses/v2
GO_LICENSES_VERSION := v2.0.1
licenses:
	go run github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION) check ./cmd/prolexic \
		--ignore github.com/dvmrry/akamai-prolexic \
		--allowed_licenses=Apache-2.0,BSD-2-Clause,BSD-3-Clause,MIT,ISC,MPL-2.0

# CI installs gitleaks with this; locally the devShell provides it.
# renovate: datasource=go depName=github.com/zricethezav/gitleaks/v8
GITLEAKS_VERSION := v8.30.1
install-gitleaks:
	go install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

# Fuzz each target for FUZZTIME (go test runs only one -fuzz target at a
# time). make check replays only the seed inputs; run this now and then.
# CI fuzzes each target weekly (.github/workflows/fuzz.yml).
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
