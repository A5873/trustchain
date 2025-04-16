# Makefile for TrustChain
#
# This Makefile provides targets for building, testing, and managing
# the TrustChain secure open source supply chain infrastructure.
#
# Environment variables:
# - GOPATH: Go workspace path (default: user's Go workspace)
# - RUSTUP_TOOLCHAIN: Rust toolchain to use (default: stable)
# - PYTHON: Python executable to use (default: python3)
# - BUILD_DIR: Directory for build artifacts (default: ./build)
# - DEBUG: Set to 1 for debug build (default: 0)
# - COVERAGE: Set to 1 to enable test coverage (default: 0)

# Build directories
BUILD_DIR ?= build
BIN_DIR = $(BUILD_DIR)/bin
LIB_DIR = $(BUILD_DIR)/lib
RUST_TARGET_DIR = target
PYTHON_BUILD_DIR = python/trustchain/build

# Go settings
GO ?= go
GOPATH ?= $(shell $(GO) env GOPATH)
GOFLAGS ?= -v
GOBUILD = $(GO) build $(GOFLAGS)
GOTEST = $(GO) test $(GOFLAGS)
GOCLEAN = $(GO) clean
GOVET = $(GO) vet
GOCOVER = -coverprofile=coverage.out -covermode=atomic
GOTESTPACKAGES = ./cmd/... ./internal/... ./pkg/...

# Rust settings
CARGO ?= cargo
RUSTUP ?= rustup
RUSTUP_TOOLCHAIN ?= stable
RUST_FEATURES ?=
ifeq ($(DEBUG), 1)
	CARGO_PROFILE = dev
else
	CARGO_PROFILE = release
endif
CARGO_BUILD_DIR = $(RUST_TARGET_DIR)/$(CARGO_PROFILE)

# Python settings
PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
PYTHON_VENV = .venv
PYTHON_ACTIVATE = . $(PYTHON_VENV)/bin/activate

# Documentation
DOCS_DIR = docs
GODOC ?= godoc
MDBOOK ?= mdbook
MDBOOK_DIR = $(DOCS_DIR)/book

# Tools
GOLANGCI_LINT ?= golangci-lint
RUSTFMT ?= rustfmt
PRETTIER ?= prettier
BLACK ?= black
ISORT ?= isort

# ==============================================================================
# Main targets
# ==============================================================================

# Default target: build all components
.PHONY: all
all: build

# Build all components
.PHONY: build
build: build-go build-rust build-python

# Run all tests
.PHONY: test
test: test-go test-rust test-python

# Clean all build artifacts
.PHONY: clean
clean: clean-go clean-rust clean-python clean-docs
	rm -rf $(BUILD_DIR)

# Lint all components
.PHONY: lint
lint: lint-go lint-rust lint-python

# Generate all documentation
.PHONY: docs
docs: docs-api docs-guide docs-book

# Setup all development dependencies
.PHONY: dev-deps
dev-deps: go-deps rust-deps python-deps tool-deps

# Update all dependencies
.PHONY: update-deps
update-deps: update-go-deps update-rust-deps update-python-deps

# Run integration tests
.PHONY: integration-test
integration-test: build
	@echo "Running integration tests..."
	@mkdir -p $(BUILD_DIR)/integration-tests
	$(GO) test -tags=integration ./test/integration/... -v

# ==============================================================================
# Go component targets
# ==============================================================================

# Build Go components
.PHONY: build-go
build-go:
	@echo "Building Go components..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/trustchain ./cmd/trustchain

# Test Go components
.PHONY: test-go
test-go:
	@echo "Testing Go components..."
ifeq ($(COVERAGE), 1)
	$(GOTEST) $(GOCOVER) $(GOTESTPACKAGES)
else
	$(GOTEST) $(GOTESTPACKAGES)
endif

# Clean Go build artifacts
.PHONY: clean-go
clean-go:
	@echo "Cleaning Go build artifacts..."
	$(GOCLEAN)
	rm -f coverage.out

# Lint Go code
.PHONY: lint-go
lint-go:
	@echo "Linting Go code..."
	$(GOVET) ./...
	$(GOLANGCI_LINT) run ./...

# Install Go dependencies
.PHONY: go-deps
go-deps:
	@echo "Installing Go dependencies..."
	$(GO) mod download
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/cmd/godoc@latest

# ==============================================================================
# Rust component targets
# ==============================================================================

# Build Rust components
.PHONY: build-rust
build-rust:
	@echo "Building Rust components..."
	@mkdir -p $(LIB_DIR)
	cd rust/crypto_core && \
	$(CARGO) build --$(CARGO_PROFILE) $(if $(RUST_FEATURES),--features "$(RUST_FEATURES)")
	cp $(CARGO_BUILD_DIR)/libtrust* $(LIB_DIR)/ 2>/dev/null || true

# Test Rust components
.PHONY: test-rust
test-rust:
	@echo "Testing Rust components..."
	cd rust/crypto_core && \
	$(CARGO) test $(if $(RUST_FEATURES),--features "$(RUST_FEATURES)")

# Clean Rust build artifacts
.PHONY: clean-rust
clean-rust:
	@echo "Cleaning Rust build artifacts..."
	cd rust/crypto_core && \
	$(CARGO) clean
	rm -rf $(RUST_TARGET_DIR)

# Lint Rust code
.PHONY: lint-rust
lint-rust:
	@echo "Linting Rust code..."
	cd rust/crypto_core && \
	$(CARGO) fmt -- --check && \
	$(CARGO) clippy

# Install Rust dependencies
.PHONY: rust-deps
rust-deps:
	@echo "Installing Rust dependencies..."
	$(RUSTUP) toolchain install $(RUSTUP_TOOLCHAIN)
	$(RUSTUP) component add clippy rustfmt
	$(CARGO) install cargo-expand cargo-audit

# Build Rust components with Python bindings
.PHONY: build-rust-python
build-rust-python:
	@echo "Building Rust components with Python bindings..."
	cd rust/crypto_core && \
	$(CARGO) build --$(CARGO_PROFILE) --features "python"

# ==============================================================================
# Python component targets
# ==============================================================================

# Build Python components
.PHONY: build-python
build-python: build-rust-python
	@echo "Building Python components..."
	cd python/trustchain && \
	$(PYTHON) setup.py build

# Test Python components
.PHONY: test-python
test-python:
	@echo "Testing Python components..."
	cd python/trustchain && \
	$(PYTEST) --cov=trustchain

# Install Python components
.PHONY: install-python
install-python: build-python
	@echo "Installing Python components..."
	cd python/trustchain && \
	$(PIP) install -e .

# Clean Python build artifacts
.PHONY: clean-python
clean-python:
	@echo "Cleaning Python build artifacts..."
	cd python/trustchain && \
	$(PYTHON) setup.py clean --all
	rm -rf $(PYTHON_BUILD_DIR) *.egg-info
	find python -name "__pycache__" -type d -exec rm -rf {} +

# Lint Python code
.PHONY: lint-python
lint-python:
	@echo "Linting Python code..."
	$(BLACK) --check python
	$(ISORT) --check-only python
	$(FLAKE8) python

# Setup Python virtual environment
.PHONY: python-venv
python-venv:
	@echo "Setting up Python virtual environment..."
	$(PYTHON) -m venv $(PYTHON_VENV)
	$(PYTHON_ACTIVATE) && $(PIP) install --upgrade pip

# Install Python dependencies
.PHONY: python-deps
python-deps: python-venv
	@echo "Installing Python dependencies..."
	$(PYTHON_ACTIVATE) && $(PIP) install -e "python/trustchain[dev,ui,integrations]"
	$(PYTHON_ACTIVATE) && $(PIP) install pytest pytest-cov black isort flake8

# ==============================================================================
# Documentation targets
# ==============================================================================

# Generate API documentation
.PHONY: docs-api
docs-api:
	@echo "Generating API documentation..."
	@mkdir -p $(DOCS_DIR)/api
	$(GODOC) -http=:8080 &
	@echo "API documentation server started at http://localhost:8080/pkg/github.com/trustchain/trustchain/"

# Generate user guide
.PHONY: docs-guide
docs-guide:
	@echo "Generating user guide..."
	@mkdir -p $(DOCS_DIR)/guide
	cd $(DOCS_DIR)/guide && \
	$(MDBOOK) build

# Generate complete documentation book
.PHONY: docs-book
docs-book:
	@echo "Generating documentation book..."
	@mkdir -p $(MDBOOK_DIR)
	cd $(MDBOOK_DIR) && \
	$(MDBOOK) build

# Clean documentation build artifacts
.PHONY: clean-docs
clean-docs:
	@echo "Cleaning documentation build artifacts..."
	rm -rf $(DOCS_DIR)/api
	rm -rf $(DOCS_DIR)/guide/book
	rm -rf $(MDBOOK_DIR)/book

# ==============================================================================
# Development tool targets
# ==============================================================================

# Install development tools
.PHONY: tool-deps
tool-deps:
	@echo "Installing development tools..."
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/cmd/godoc@latest
	$(CARGO) install mdbook
	$(PIP) install black isort flake8 pytest pytest-cov

# Setup git hooks
.PHONY: hooks
hooks:
	@echo "Setting up git hooks..."
	cp scripts/pre-commit .git/hooks/
	chmod +x .git/hooks/pre-commit

# Run pre-commit checks
.PHONY: pre-commit
pre-commit: lint

# ==============================================================================
# Package and release targets
# ==============================================================================

# Create distribution packages
.PHONY: dist
dist: build
	@echo "Creating distribution packages..."
	@mkdir -p $(BUILD_DIR)/dist
	# Create Linux package
	tar -czf $(BUILD_DIR)/dist/trustchain-linux-amd64.tar.gz -C $(BIN_DIR) trustchain
	# Create macOS package
	tar -czf $(BUILD_DIR)/dist/trustchain-macos-amd64.tar.gz -C $(BIN_DIR) trustchain
	# Create Windows package
	zip -j $(BUILD_DIR)/dist/trustchain-windows-amd64.zip $(BIN_DIR)/trustchain.exe

# Create release
.PHONY: release
release: dist
	@echo "Creating release..."
	@echo "Release created in $(BUILD_DIR)/dist"

# ==============================================================================
# Helper targets
# ==============================================================================

# Print version information
.PHONY: version
version:
	@echo "TrustChain Version Information:"
	@echo "Go version: $(shell $(GO) version)"
	@echo "Rust version: $(shell $(CARGO) --version)"
	@echo "Python version: $(shell $(PYTHON) --version)"

# Run the CLI for development
.PHONY: run
run: build
	@echo "Running TrustChain CLI..."
	$(BIN_DIR)/trustchain

# Show help information
.PHONY: help
help:
	@echo "TrustChain Makefile Help"
	@echo "========================="
	@echo ""
	@echo "Main targets:"
	@echo "  all                Build all components (default)"
	@echo "  build              Build all components"
	@echo "  test               Run all tests"
	@echo "  clean              Clean all build artifacts"
	@echo "  lint               Lint all components"
	@echo "  docs               Generate all documentation"
	@echo "  dev-deps           Setup all development dependencies"
	@echo "  integration-test   Run integration tests"
	@echo ""
	@echo "Go targets:"
	@echo "  build-go           Build Go components"
	@echo "  test-go            Test Go components"
	@echo "  clean-go           Clean Go build artifacts"
	@echo "  lint-go            Lint Go code"
	@echo "  go-deps            Install Go dependencies"
	@echo ""
	@echo "Rust targets:"
	@echo "  build-rust         Build Rust components"
	@echo "  test-rust          Test Rust components"
	@echo "  clean-rust         Clean Rust build artifacts"
	@echo "  lint-rust          Lint Rust code"
	@echo "  rust-deps          Install Rust dependencies"
	@echo ""
	@echo "Python targets:"
	@echo "  build-python       Build Python components"
	@echo "  test-python        Test Python components"
	@echo "  install-python     Install Python components"
	@echo "  clean-python       Clean Python build artifacts"
	@echo "  lint-python        Lint Python code"
	@echo "  python-venv        Setup Python virtual environment"
	@echo "  python-deps        Install Python dependencies"
	@echo ""
	@echo "Documentation targets:"
	@echo "  docs-api           Generate API documentation"
	@echo "  docs-guide         Generate user guide"
	@echo "  docs-book          Generate complete documentation book"
	@echo "  clean-docs         Clean documentation build artifacts"
	@echo ""
	@echo "Development tool targets:"
	@echo "  tool-deps          Install development tools"
	@echo "  hooks              Setup git hooks"
	@echo "  pre-commit         Run pre-commit checks"
	@echo ""
	@echo "Package and release targets:"
	@echo "  dist               Create distribution packages"
	@echo "  release            Create release"
	@echo ""
	@echo "Helper targets:"
	@echo "  version            Print version information"
	@echo "  run                Run the CLI for development"
	@echo "  help               Show this help message"

