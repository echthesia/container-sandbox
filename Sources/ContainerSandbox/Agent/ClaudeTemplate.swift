struct ClaudeTemplate: AgentTemplate {
    let name = "claude"
    let defaultImage = "container-sandbox-claude:latest"

    let entrypoint = ["/home/sandbox/.local/bin/claude", "--dangerously-skip-permissions"]

    let defaultEnvironment: [String: String] = [
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    let passthroughEnvironment = [
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ]

    let requiresSSH = true
    let requiresVirtualization = false
    let useInit = true
    let defaultNetworkPolicy = NetworkPolicy.allow

    let containerfileContent: String? = ##"""
    FROM docker.io/ubuntu:26.04

    ENV DEBIAN_FRONTEND=noninteractive

    RUN apt-get update && apt-get install -y \
        build-essential \
        ca-certificates \
        curl \
        dnsutils \
        gh \
        git \
        gnupg \
        jq \
        less \
        locales \
        lsof \
        make \
        openssh-client \
        procps \
        psmisc \
        rsync \
        socat \
        sudo \
        unzip \
        vim \
        wget \
        zsh \
        && rm -rf /var/lib/apt/lists/*

    RUN locale-gen en_US.UTF-8
    ENV LANG=en_US.UTF-8
    ENV LC_ALL=en_US.UTF-8

    RUN useradd -m -s /bin/bash -G sudo sandbox \
        && echo "sandbox ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/sandbox

    RUN git config --system init.defaultBranch main \
        && git config --system safe.directory '*'

    # uv vendored from Astral's official image — pinned, checksum-verified upstream.
    COPY --from=ghcr.io/astral-sh/uv:0.11.7 /uv /usr/local/bin/uv

    USER sandbox
    WORKDIR /home/sandbox
    ENV PATH="/home/sandbox/.local/bin:$PATH"

    # Pre-create state dirs so OCI bind-mounts don't create them root-owned.
    RUN mkdir -p /home/sandbox/.local/bin /home/sandbox/.local/share /home/sandbox/.local/state

    RUN curl -fsSL https://claude.ai/install.sh | bash
    """##
}
