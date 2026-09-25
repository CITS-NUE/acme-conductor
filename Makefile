# Makefile for ACME Conductor.
#
# Build metadata is derived from git at build time and injected via
# -ldflags into internal/version. See internal/version/version.go.

MODULE      := github.com/CITS-NUE/acme-conductor
BIN_DIR     := bin
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# lego CLI bundled into the runner image (Dockerfile.runner). The version
# here must match the LEGO_SHA256_AMD64 / LEGO_SHA256_ARM64 checksum
# defaults declared in Dockerfile.runner, which remain the single source
# of truth for those checksums.
LEGO_VERSION ?= 4.35.2

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(BUILD_DATE)

IMAGE_REGISTRY := ghcr.io/cits-nue
IMAGE_TAG      := dev

.PHONY: build fmt fmt-fix vet test test-race vulncheck image-conductor image-runner images verify punct

## build: compile both binaries into bin/ with version metadata baked in.
build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/acme-conductor ./cmd/acme-conductor
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/acme-runner ./cmd/acme-runner

## fmt: fail if any Go file is not gofmt-formatted.
fmt:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

## fmt-fix: reformat all Go files in place.
fmt-fix:
	gofmt -w .

## vet: run go vet across the module.
vet:
	go vet ./...

## test: run the unit test suite.
test:
	go test ./...

## test-race: run the unit test suite with the race detector.
test-race:
	go test -race ./...

## vulncheck: run govulncheck against the module.
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## image-conductor: build the acme-conductor container image.
image-conductor:
	docker build -f Dockerfile.conductor \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE_REGISTRY)/acme-conductor:$(IMAGE_TAG) .

## image-runner: build the acme-runner container image.
image-runner:
	docker build -f Dockerfile.runner \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg LEGO_VERSION=$(LEGO_VERSION) \
		-t $(IMAGE_REGISTRY)/acme-runner:$(IMAGE_TAG) .

## images: build both container images.
images: image-conductor image-runner

# The ideographic comma and full stop (U+3001, U+3002), spelled as UTF-8
# bytes so that this file does not trip its own check.
JA_COMMA    := $(shell printf '\343\200\201')
JA_PERIOD   := $(shell printf '\343\200\202')

## punct: fail if any tracked file uses U+3001 or U+3002; Japanese text uses ， and ．.
punct:
	@if git grep -nF -e '$(JA_COMMA)' -e '$(JA_PERIOD)'; then \
		echo "Use ， and ． instead of U+3001 and U+3002 (see CONTRIBUTING.md)."; \
		exit 1; \
	fi

## verify: run the full local verification suite (fmt, punct, vet, test, test-race).
verify: fmt punct vet test test-race
