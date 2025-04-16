```
  _______             _    _____ _           _
 |__   __|           | |  / ____| |         (_)
    | |_ __ _   _ ___| |_| |    | |__   __ _ _ _ __
    | | '__| | | / __| __| |    | '_ \ / _` | | '_ \
    | | |  | |_| \__ \ |_| |____| | | | (_| | | | | |
    |_|_|   \__,_|___/\__|\_____|_| |_|\__,_|_|_| |_|

    [][][]──────[][]────[][]──[][]────[][][]
    [][][]──────[][]────[][]──[][]────[][][]
     ▀▀▀        ▀▀      ▀▀  ▀▀      ▀▀▀
     Secure Open Source Supply Chain Infrastructure
```

# TrustChain: Secure Open Source Supply Chain Infrastructure

[![CI Status](https://github.com/A5873/trustchain/workflows/go/badge.svg)](https://github.com/A5873/trustchain/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Project Status

TrustChain is currently in early development (Phase 1). We're focusing on building the core cryptographic functionality.

**Completed:**
- ✅ Key generation and management
- ✅ Digital signature creation and verification
- ✅ Hash functions and verification
- ✅ Verification policies and trust chains
- ✅ Development environment setup

**In Progress:**
- 🚧 Cryptographic primitives FFI for Go integration
- 🚧 Basic CLI for crypto operations

**Coming Soon:**
- Distributed verification protocol
- Package manager integrations
- CI/CD integrations

For more details on our roadmap, see the [Strategy Document](docs/STRATEGY.md).

## Vision

TrustChain is a lightweight, distributed verification system for open source software components that establishes cryptographic proof of code integrity throughout the development lifecycle. The system combines Git-compatible cryptographic signing with distributed attestation nodes running on a peer-to-peer network to create verifiable chains of custody for code—from individual contributor commits to production deployments.

Our vision is to restore and strengthen trust in open source software by providing transparent, non-invasive security measures that respect the distributed nature of open source while providing tangible security benefits.

## Key Features

- **Cryptographic Verification**: End-to-end cryptographic proof of code integrity from commit to deployment
- **Distributed Attestation**: Peer-to-peer network of attestation nodes for decentralized verification
- **Trust Zones**: Customizable verification requirements without sacrificing development velocity
- **Automated Anomaly Detection**: Configurable policy engines to identify suspicious changes
- **Low Overhead**: Sub-5% performance overhead on build processes
- **Seamless Integration**:
  - Major package managers (npm, pip, cargo, apt)
  - Containerization platforms (Docker, Podman)
  - CI/CD pipelines
- **Visualization Dashboards**: Intuitive interfaces for monitoring trust metrics

## Architecture Overview

TrustChain employs a hybrid architecture designed for performance, security, and usability:

```
┌─────────────────────────────────────────────────┐
│                User Interfaces                  │
│  CLI Tools | Web Dashboards | IDE Integrations  │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│              Python Interface Layer             │
│    API Wrappers | Integrations | Dashboards     │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│              Core Services (Go)                 │
│ Orchestration | Trust Zones | Policy Engine     │
└─┬────────────────────────────────────────────┬──┘
  │                                            │
┌─▼───────────────────────┐   ┌────────────────▼─┐
│  P2P Network (Go)       │   │ Crypto Core(Rust)│
│ Node Discovery          │   │ Verification     │
│ Consensus Protocol      │   │ Signing          │
│ Attestation Distribution│   │ Hash Functions   │
└─────────────────────────┘   └──────────────────┘
```

### Component Structure

1. **Rust Components** (Performance-critical cryptographic operations)
   - Cryptographic verification engine
   - Signature validation
   - Hash calculation and verification
   - Low-level binary analysis

2. **Go Components** (Network and orchestration)
   - P2P network management
   - Distributed attestation protocol
   - Trust zone implementation
   - Core verification services

3. **Python Layer** (Interface and integration)
   - API wrappers for developer use
   - Integration plugins for package managers and CI/CD
   - Visualization dashboards
   - Policy configuration tools

## Getting Started

### Prerequisites

- Go 1.24+
- Rust 1.67+
- Python 3.10+
- OpenSSL 3.0+
- Docker (for containerized development)

### Installation

> **Note:** TrustChain is in active development and not yet ready for production use.
> The installation instructions below will be available once we reach alpha release.

#### Development Setup

```bash
# Clone the repository
git clone https://github.com/A5873/trustchain.git
cd trustchain

# Set up development environment
make dev-deps

# Build all components
make build

# Run tests
make test
```

#### Using Dev Container

We provide a development container configuration for Visual Studio Code and GitHub Codespaces:

1. Install [VS Code](https://code.visualstudio.com/) and the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Clone the repository and open it in VS Code
3. When prompted, click "Reopen in Container"
4. The container will set up all required dependencies automatically

## Basic Usage

### Signing a Project

```bash
# Initialize TrustChain in your project
trustchain init

# Configure trust zones (minimal example)
trustchain zone create --name production --policy standard

# Sign your code
trustchain sign --zone production
```

### Verifying Dependencies

```bash
# Verify all dependencies in a project
trustchain verify ./my-project

# Verify a specific package
trustchain verify-package numpy==1.24.0

# Integrate with package installation
pip install numpy==1.24.0 --trustchain-verify
```

### CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Verify dependencies with TrustChain
  uses: trustchain/verify-action@v1
  with:
    path: .
    policy: standard
```

## Development Setup

1. **Setup Development Environment**

```bash
# Install development dependencies
make dev-deps

# Setup pre-commit hooks
make hooks
```

2. **Running Tests**

```bash
# Run all tests
make test

# Run specific component tests
make test-rust
make test-go
make test-python
```

3. **Building Documentation**

```bash
make docs
```

## Documentation

For more detailed information about TrustChain, please refer to:

- [Strategy Document](docs/STRATEGY.md) - Project roadmap and architecture
- [Contributing Guidelines](CONTRIBUTING.md) - How to contribute to the project
- [Security Policy](.github/SECURITY.md) - Security considerations and reporting
- API Documentation - *(Coming Soon)*
- Integration Guides - *(Coming Soon)*

## Security

Security is our top priority. For information about our security policy and how to report security issues, please see our [Security Policy](.github/SECURITY.md).

### Reporting a Vulnerability

We take all security vulnerabilities seriously. Please report them via email to security@trustchain.example.org rather than creating public GitHub issues.

## Contributing

We welcome contributions from the community! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to get started, coding standards, and the pull request process.

## Authors

- **Alex Ngugi** - *Initial work* - [A5873](https://github.com/A5873)

See also the list of [contributors](https://github.com/A5873/trustchain/contributors) who have participated in this project.

## License

TrustChain is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
