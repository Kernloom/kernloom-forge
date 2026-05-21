GO       := $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
BINARY   := bin/forge
CMD      := ./cmd/forge
REGISTRY := registries/core
NODES    := examples/nodes
POLICIES := examples/policies

.PHONY: all build test test-verbose cover lint clean \
        validate-registry validate-nodes validate-policies validate \
        compile-example

all: build test

# ── Build ─────────────────────────────────────────────────────────────────────

build:
	$(GO) build -o $(BINARY) $(CMD)

# ── Test ──────────────────────────────────────────────────────────────────────

test:
	$(GO) test ./...

test-verbose:
	$(GO) test -v ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

# ── Lint ──────────────────────────────────────────────────────────────────────

lint:
	$(GO) vet ./...

# ── Validate (no build step needed) ──────────────────────────────────────────

validate-registry:
	$(GO) run $(CMD) registry validate $(REGISTRY)

validate-nodes:
	@for f in $(NODES)/*.yaml; do \
		echo "  checking $$f"; \
		$(GO) run $(CMD) adapter validate $$f --registry $(REGISTRY) || exit 1; \
	done
	@echo "OK  all node definitions valid"

validate-policies:
	@for f in $(POLICIES)/*.yaml; do \
		echo "  checking $$f"; \
		$(GO) run $(CMD) policy validate $$f --registry $(REGISTRY) || exit 1; \
	done
	@echo "OK  all policies valid"

validate: validate-registry validate-nodes validate-policies

# ── Compile example ───────────────────────────────────────────────────────────

compile-example:
	$(GO) run $(CMD) compile $(POLICIES)/mitigate-connection-spike.yaml \
		--registry $(REGISTRY) \
		--nodes $(NODES)

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARY) coverage.out coverage.html
