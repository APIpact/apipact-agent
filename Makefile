SHELL := /bin/bash
BIN   := bin
PKG   := github.com/APIpact/apipact-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

CMDS := supervisor worker agentctl release-sign

.PHONY: all build test vet tidy clean checksums sbom verify $(CMDS)

all: build

build: $(CMDS)

# Reproducible flags: no cgo, -trimpath, pinned deps (go.mod/go.sum).
$(CMDS):
	@mkdir -p $(BIN)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/apipact-$@ ./cmd/$@

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

# checksums emits the SHA-256 of every built binary so a recipient can confirm a
# binary matches a build of this source (see TRUST.md §8).
checksums: build
	@cd $(BIN) && sha256sum apipact-* | tee SHA256SUMS

# sbom emits the exact, version-pinned module inventory embedded in each binary.
sbom: build
	@for b in $(BIN)/apipact-*; do \
		echo "== $$b =="; \
		go version -m $$b | grep -E '^\s+(dep|=>)' ; \
	done | tee $(BIN)/SBOM.txt

# verify runs the full trust gate: format, vet, and the complete test suite
# (incl. the live self-update + rollback tests).
verify: vet test
	@echo "gofmt check:"; test -z "$$(gofmt -l . )" && echo "  clean" || (gofmt -l . ; exit 1)

clean:
	rm -rf $(BIN)
