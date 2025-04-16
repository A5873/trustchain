# Contributing to TrustChain

Thank you for considering contributing to TrustChain! We welcome contributions from everyone, regardless of experience level. This document provides guidelines and instructions to help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Multi-language Development](#multi-language-development)
- [Code Style Guidelines](#code-style-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

All contributors are expected to adhere to our Code of Conduct. Please be respectful, inclusive, and constructive in all interactions.

- We value diverse perspectives and experiences
- We show empathy towards other community members
- We focus on what's best for the community and the project
- We give and gracefully accept constructive feedback

## Development Setup

TrustChain is a multi-language project with components written in Go, Rust, and Python. You'll need to set up development environments for each language.

### Prerequisites

- Go 1.20+
- Rust 1.65+
- Python 3.10+
- OpenSSL 3.0+
- Docker (for integration testing)
- Git

### Getting Started

1. **Fork the repository:**
   
   Start by forking the repository on GitHub, then clone your fork:

   ```bash
   git clone https://github.com/YOUR-USERNAME/trustchain.git
   cd trustchain
   git remote add upstream https://github.com/trustchain/trustchain.git
   ```

2. **Install development dependencies:**

   ```bash
   make dev-deps
   ```

   This will install all development dependencies for Go, Rust, and Python components.

3. **Set up pre-commit hooks:**

   ```bash
   make hooks
   ```

4. **Create a new branch for your feature or fix:**

   ```bash
   git checkout -b feature/your-feature-name
   ```

## Multi-language Development

TrustChain uses a hybrid architecture with components in multiple languages:

### Go Components

- Located in `cmd/`, `internal/`, and `pkg/` directories
- Responsible for CLI, core services, and P2P networking
- Build with `make build-go`
- Test with `make test-go`

### Rust Components

- Located in the `rust/` directory
- Responsible for performance-critical cryptographic operations
- Build with `make build-rust`
- Test with `make test-rust`

### Python Components

- Located in the `python/` directory
- Responsible for API wrappers, integrations, and dashboards
- Install development version with `make install-python-dev`
- Test with `make test-python`

### Cross-language Interaction

The languages interact through well-defined interfaces:

- Go to Rust: Using CGO bindings for Rust libraries
- Python to Go: Using gRPC and/or REST APIs exposed by Go services

When making changes, consider the impact on other language components.

## Code Style Guidelines

We follow language-specific code style guidelines:

### Go

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` to format code
- Document all exported functions, types, and packages
- Run `golint` and `go vet` before submitting code

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` to format code
- Document all public functions with appropriate documentation comments
- Run `clippy` before submitting code: `cargo clippy -- -D warnings`

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use Black for code formatting: `black .`
- Use type hints where appropriate
- Document all public functions, classes, and methods with docstrings

## Pull Request Process

1. **Ensure your code follows the style guidelines**
   
   Run the linting and formatting tools for the language you're working with.

2. **Write comprehensive tests**
   
   Add tests that cover your changes and ensure all tests pass.

3. **Update documentation**
   
   Update relevant documentation to reflect your changes.

4. **Submit your PR**

   Create a pull request against the `main` branch of the original repository.

5. **PR Description**

   Provide a clear description of the changes:
   - What problem does it solve?
   - How does it solve the problem?
   - Any breaking changes?
   - Screenshots or output examples if relevant

6. **Code Review**

   Address any review comments and iterate on your solution.

7. **Approval and Merge**

   Once approved, a maintainer will merge your PR.

## Testing

Testing is critical for TrustChain's security and reliability:

### Unit Tests

- Write unit tests for all new functionality
- Ensure tests are deterministic and isolated
- Test edge cases and error conditions

### Integration Tests

- Cross-language tests are in the `integration/` directory
- Run with `make integration-test`

### Security Testing

- Security-sensitive code should include specific security tests
- Consider attack vectors specific to cryptographic systems

## Documentation

Good documentation is essential:

- Document all public APIs
- Update README.md for significant changes
- Include clear examples for new features
- Document architecture decisions in `docs/architecture/`
- Update API documentation when interfaces change

## Community

Join our community to get help or discuss ideas:

- [GitHub Discussions](https://github.com/trustchain/trustchain/discussions) for feature ideas and general questions
- [Issue Tracker](https://github.com/trustchain/trustchain/issues) for bugs and tasks
- [Discord](https://discord.gg/trustchain) for real-time chat and collaboration

## Release Process

TrustChain follows semantic versioning. The release process is:

1. Version branches created from `main` (e.g., `release/v1.2.0`)
2. Release testing and stabilization on the branch
3. Creation of a signed tag for the final release
4. Automated deployment to package repositories

Contributors aren't expected to create releases, but should be aware of the versioning scheme when making changes.

---

Thank you for contributing to TrustChain! Your efforts help secure the open source ecosystem for everyone.

