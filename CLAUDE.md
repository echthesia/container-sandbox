# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A Swift CLI plugin for Apple's Container framework that creates isolated sandbox environments for AI coding agents. Installed as a `container` subcommand (`container sandbox ...`).

- macOS 26+, Swift 6.2, strict concurrency (`Sendable` throughout)
- Depends on `apple/container` (0.11.0) and `swift-argument-parser`
- Go 1.23 module under `init-image/` for in-container helpers (Linux-targeted)

## Build / Test / Install

```
make build          # swift build -c release
make init-binaries  # cross-compile Linux helpers (proxy-bridge, sandbox-init)
make install        # build + init-binaries + codesign + symlink into container plugin dir
make verify         # swiftlint + swift test
make clean          # swift package clean + remove init-image binaries
```

The Swift binary **must be codesigned** after copying (`codesign -fs -`). `make install` handles this.

Install layout:
- `~/.local/lib/container-sandbox/bin/sandbox` — Swift CLI
- `~/.local/lib/container-sandbox/libexec/{proxy-bridge,sandbox-init}` — Linux helpers, mounted into containers via virtiofs
- `$(brew --prefix container)/libexec/container-plugins/sandbox` — symlink to the stable dir

## Architecture

- `Sources/ContainerSandbox/CLI/SandboxCommand.swift` — all ArgumentParser commands (`run`, `create`, `exec`, `ls`, `stop`, `rm`, `save`, `network proxy ...`)
- `Sources/ContainerSandbox/Sandbox/` — `SandboxManager` (lifecycle via ContainerClient), `SessionTracker` (auto-stop on last session exit), `SandboxNaming`, `ContainerOperations`
- `Sources/ContainerSandbox/Agent/` — `AgentTemplate` protocol + registry; `ClaudeTemplate`, `ShellTemplate` (image content lives in inline `containerfileContent` literals, no separate Containerfiles/ dir)
- `Sources/ContainerSandbox/Network/` — `ProxyServer` (host-side SOCKS5 + HTTP CONNECT proxy on a Unix socket), `NetworkPolicy`, `DomainFilter`, `ProxyManager` (per-sandbox proxy lifecycle)
- `Sources/ContainerSandbox/Utilities/` — `Errors`, `HostPort` (shared host-string normalization)
- `init-image/cmd/sandbox-init/` — Go init wrapper: PID 2 under vminitd, spawns proxy-bridge and (if `/usr/bin/dockerd` is present) dockerd
- `init-image/cmd/proxy-bridge/` — Go TCP↔UDS relay: listens on `127.0.0.1:3128` inside the container and forwards to the host's per-sandbox proxy over a shared Unix socket at `/run/proxy.sock`

## Key patterns

- **Environment layering**: image env < template env < host passthrough < caller extras (last-writer-wins dedup)
- **Deterministic naming**: sandbox names include SHA256(workspace path) prefix to avoid collisions
- **Session tracking**: host-side PID files in `~/.local/state/container-sandbox/sessions/`
- **Init process**: `sandbox-init` (Go) runs as PID 2 under vminitd, started via the container's `process` config; agents run via `exec`
- **Network egress**: agent traffic → in-container `127.0.0.1:3128` (proxy-bridge) → virtiofs UDS at `/run/proxy.sock` → host `ProxyServer` → policy-filtered outbound
- **Nested Docker**: ClaudeTemplate installs Docker Engine; nested containers reach proxy-bridge through `172.17.0.1:3128` via per-user docker config

## Container API

The Apple Container API docs are JS-rendered DoCC — they cannot be fetched or read directly. When you need API details, **read the source code** from the `apple/container` package (in `.build/checkouts/container/`) rather than trying to fetch documentation URLs.
