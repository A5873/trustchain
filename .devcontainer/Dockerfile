FROM ubuntu:22.04

# Avoid prompts during package installation
ARG DEBIAN_FRONTEND=noninteractive

# Set shell to bash with pipefail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install basic tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    libssl-dev \
    llvm \
    lsb-release \
    make \
    pkg-config \
    software-properties-common \
    unzip \
    wget \
    zsh \
    # Add additional tools
    vim \
    htop \
    tmux \
    less \
    ssh \
    sudo \
    # Add libraries needed for cryptographic operations
    libsodium-dev \
    # Cleanup
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Setup Go 1.24
ARG GO_VERSION=1.24.2
RUN curl -fsSL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xzf - \
    && echo 'export PATH=$PATH:/usr/local/go/bin:/go/bin' >> /etc/profile \
    && echo 'export GOPATH=/go' >> /etc/profile

# Install Go tools
ENV PATH=$PATH:/usr/local/go/bin:/go/bin
ENV GOPATH=/go
RUN mkdir -p /go/bin && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install golang.org/x/tools/gopls@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    go install golang.org/x/tools/cmd/goimports@latest && \
    go install golang.org/x/lint/golint@latest

# Install Rust
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=$PATH:/usr/local/cargo/bin
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable \
    && chmod -R a+w ${RUSTUP_HOME} ${CARGO_HOME}

# Install Rust components and tools
RUN rustup component add rustfmt clippy rust-src \
    && cargo install cargo-edit cargo-watch cargo-audit cargo-tarpaulin

# Install Python 3.10
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.10 \
    python3.10-dev \
    python3.10-venv \
    python3-pip \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/bin/python3.10 /usr/bin/python3 \
    && ln -s /usr/bin/python3 /usr/bin/python

# Install Python tools
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel \
    && pip3 install --no-cache-dir \
    black \
    isort \
    mypy \
    pytest \
    pytest-cov \
    pylint \
    flake8 \
    grpcio-tools \
    twine \
    build

# Install protobuf compiler
RUN wget -O protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v3.20.0/protoc-3.20.0-linux-x86_64.zip \
    && unzip -o protoc.zip -d /usr/local bin/protoc \
    && unzip -o protoc.zip -d /usr/local 'include/*' \
    && rm protoc.zip

# Create a non-root user with sudo access
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Set up Oh My Zsh for better terminal experience
USER $USERNAME
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended \
    && git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${HOME}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting \
    && git clone https://github.com/zsh-users/zsh-autosuggestions ${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions \
    && sed -i 's/plugins=(git)/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/g' ${HOME}/.zshrc

# Configure environment for user
USER $USERNAME
RUN echo 'export PATH=$PATH:/usr/local/go/bin:/go/bin:/usr/local/cargo/bin' >> ~/.zshrc \
    && echo 'export GOPATH=/go' >> ~/.zshrc \
    && echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc

# Switch back to root for any additional installations
USER root

# Install direnv for environment management
RUN curl -sfL https://direnv.net/install.sh | bash

# Setup workspace directory
WORKDIR /workspace
RUN chown $USERNAME:$USERNAME /workspace

# Switch back to user to finish setup
USER $USERNAME

# Set up git config
RUN git config --global --add safe.directory /workspace

# Switch back to default shell (zsh)
CMD ["zsh"]

