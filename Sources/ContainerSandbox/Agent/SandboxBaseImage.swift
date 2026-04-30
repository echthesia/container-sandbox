/// Shared Containerfile fragment used by every agent template.
///
/// Provides ubuntu + common CLI tools + Node.js + Docker Engine + the
/// unprivileged `sandbox` user with NOPASSWD sudo and per-user docker
/// proxy config. Each template appends its own `RUN` to install its
/// agent binary; the user, workdir, PATH, and npm prefix are already set.
enum SandboxBaseImage {
    static let containerfileContent: String = ##"""
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

        # Node.js 22 LTS for agents distributed via npm (Codex, Gemini, Copilot).
        RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
            && apt-get install -y --no-install-recommends nodejs \
            && rm -rf /var/lib/apt/lists/*

        # Docker Engine for nested containers. Each sandbox runs in its own VM,
        # so dockerd's privileges stay inside that hypervisor boundary.
        RUN install -m 0755 -d /etc/apt/keyrings \
            && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc \
            && chmod a+r /etc/apt/keyrings/docker.asc \
            && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list \
            && apt-get update && apt-get install -y --no-install-recommends \
                docker-ce \
                docker-ce-cli \
                containerd.io \
                docker-buildx-plugin \
                docker-compose-plugin \
            && rm -rf /var/lib/apt/lists/*

        # dockerd's own image pulls go through proxy-bridge on 127.0.0.1:3128.
        RUN mkdir -p /etc/docker && printf '%s\n' \
            '{' \
            '  "proxies": {' \
            '    "http-proxy": "http://127.0.0.1:3128",' \
            '    "https-proxy": "http://127.0.0.1:3128",' \
            '    "no-proxy": "localhost,127.0.0.1,::1"' \
            '  }' \
            '}' > /etc/docker/daemon.json

        RUN useradd -m -s /bin/bash -G sudo,docker sandbox \
            && echo "sandbox ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/sandbox

        # Inject HTTP_PROXY into nested containers via docker's per-user config.
        # Nested containers reach proxy-bridge through the docker bridge gateway
        # (172.17.0.1 by default); intra-bridge and loopback traffic skip the proxy.
        RUN install -d -o sandbox -g sandbox /home/sandbox/.docker && printf '%s\n' \
            '{' \
            '  "proxies": {' \
            '    "default": {' \
            '      "httpProxy": "http://172.17.0.1:3128",' \
            '      "httpsProxy": "http://172.17.0.1:3128",' \
            '      "noProxy": "localhost,127.0.0.1,::1,172.17.0.0/16"' \
            '    }' \
            '  }' \
            '}' > /home/sandbox/.docker/config.json \
            && chown sandbox:sandbox /home/sandbox/.docker/config.json

        RUN git config --system init.defaultBranch main \
            && git config --system safe.directory '*'

        # uv vendored from Astral's official image — pinned, checksum-verified upstream.
        COPY --from=ghcr.io/astral-sh/uv:0.11.7 /uv /usr/local/bin/uv

        USER sandbox
        WORKDIR /home/sandbox
        # ~/.local/bin holds user installs (uv, claude, opencode); npm globals also
        # land here via NPM_CONFIG_PREFIX so we don't need sudo for `npm i -g`.
        ENV PATH="/home/sandbox/.local/bin:$PATH"
        ENV NPM_CONFIG_PREFIX=/home/sandbox/.local

        # Pre-create state dirs so OCI bind-mounts don't create them root-owned.
        RUN mkdir -p /home/sandbox/.local/bin /home/sandbox/.local/share /home/sandbox/.local/state
        """##
}
