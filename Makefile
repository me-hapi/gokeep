.PHONY: all build run test test-race cover fmt vet lint sec vuln tidy ci clean

GO ?= go
BINARY := fort
PKG := ./...
COVERAGE_FILE := coverage.out

# Default target. Builds the binary.
all: build

# Build the fort binary. -trimpath strips local paths for reproducible builds.
build:
	CGO_ENABLED=0 GOFLAGS=-trimpath $(GO) build -o $(BINARY) ./cmd/fort

# Run the CLI from source.
run:
	$(GO) run ./cmd/fort

# Run all tests. -count=1 disables test result caching.
test:
	$(GO) test -count=1 $(PKG)

# Run tests with the race detector. Mandatory for any concurrency-related change.
test-race:
	$(GO) test -race -count=1 $(PKG)

# Run tests with coverage. Open coverage.html in browser to view per-line coverage.
cover:
	$(GO) test -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(PKG)
	$(GO) tool cover -func=$(COVERAGE_FILE)
	$(GO) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report: coverage.html"

# Auto-format code with gofmt and goimports. Run before commit.
fmt:
	$(GO) fmt $(PKG)
	@command -v goimports >/dev/null 2>&1 && goimports -w . || echo "goimports not installed (skipping): go install golang.org/x/tools/cmd/goimports@latest"

# Run go vet. Built-in static analysis. Always run in CI.
vet:
	$(GO) vet $(PKG)

# Run golangci-lint (aggregator: gosec, staticcheck, errcheck, etc.).
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed: https://golangci-lint.run/welcome/install/"; exit 1; }
	golangci-lint run

# Run gosec (security linter). CI gate.
sec:
	@command -v gosec >/dev/null 2>&1 || { echo "gosec not installed: go install github.com/securego/gosec/v2/cmd/gosec@latest"; exit 1; }
	gosec -fmt=text -confidence=high -severity=high ./...

# Run govulncheck (vulnerability scanner for dependencies). CI gate.
vuln:
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck not installed: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck $(PKG)

# Run go mod tidy. Run after every dep change.
tidy:
	$(GO) mod tidy

# Run all checks in order. Use before commit and in CI.
ci: tidy fmt vet lint test-race sec vuln
	@echo ""
	@echo "All checks passed."

# Remove build artifacts.
clean:
	rm -f $(BINARY) $(COVERAGE_FILE) coverage.html
