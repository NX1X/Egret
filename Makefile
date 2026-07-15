# Egret — build & dev tasks.
#
# eBPF codegen (`make generate`) and the full Linux build require a Linux host
# with clang + kernel BTF. The cross-platform packages build anywhere.

BINARY      := egret
PKG         := github.com/NX1X/Egret
CMD         := ./cmd/egret
BIN_DIR     := bin

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X $(PKG)/internal/cli.version=$(VERSION) \
	-X $(PKG)/internal/cli.commit=$(COMMIT) \
	-X $(PKG)/internal/cli.date=$(DATE)

# Packages that build WITHOUT generated eBPF bindings (no collector import).
# Safe to test on any platform / before `make generate`.
PURE_PKGS := ./internal/policy/... ./internal/report/... ./internal/audit/... \
	./internal/event/... ./internal/monitor/... ./internal/enforcer/... \
	./internal/sarif/... ./internal/ingest/...

.PHONY: all generate vmlinux build build-static test test-pure cover test-e2e lint vet fmt tidy clean

all: build

VMLINUX := internal/bpf/vmlinux.h

## vmlinux: generate the CO-RE header from the running kernel's BTF (bpftool + BTF).
##   Generated (not vendored); regenerated when missing. CI needs bpftool + a
##   kernel exposing /sys/kernel/btf/vmlinux (GitHub ubuntu runners do).
$(VMLINUX):
	@command -v bpftool >/dev/null || { echo "bpftool not found: apt install linux-tools-generic (or linux-tools-common)"; exit 1; }
	@test -f /sys/kernel/btf/vmlinux || { echo "kernel BTF missing (/sys/kernel/btf/vmlinux) — need a BTF-enabled kernel"; exit 1; }
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

vmlinux: $(VMLINUX)

## generate: compile eBPF C and emit Go bindings (Linux + clang + bpftool required).
generate: $(VMLINUX)
	go generate ./...

## build: build the egret binary into ./bin (run `make generate` first on Linux).
build:
	mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)

## build-static: fully static binary for CI runners / containers.
build-static:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)

## test: run all unit tests (needs `make generate` first for cli/collector).
test:
	go test ./...

## test-pure: tests that need no eBPF codegen (run anywhere, pre-generate).
test-pure:
	go test $(PURE_PKGS)

## cover: coverage for the pure packages, with an HTML report.
cover:
	go test -coverprofile=coverage.out $(PURE_PKGS)
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

## test-e2e: end-to-end tests against a real kernel (Linux, root, post-generate).
test-e2e:
	sudo -E env "PATH=$$PATH" go test -tags e2e -v ./test/...

## vet / fmt / tidy: hygiene.
vet:
	go vet ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

## lint: vet + gofmt check (CI fails on unformatted code).
lint: vet
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: files need formatting" && exit 1)

clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html
	rm -f internal/collector/*_bpfel.go internal/collector/*_bpfeb.go
	rm -f internal/collector/*_bpfel.o internal/collector/*_bpfeb.o
	rm -f internal/bpf/vmlinux.h
