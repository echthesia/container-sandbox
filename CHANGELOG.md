# Changelog

All notable changes to this project will be documented here. Format roughly
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project intends to follow [SemVer](https://semver.org) once it stabilizes;
0.x releases may include breaking changes between minor versions.

## [Unreleased]

## [0.1.0] — 2026-05-03

First public release. Run AI coding agents inside isolated microVM
sandboxes via the `container sandbox` subcommand.

### Added

- **Six built-in agent templates**: `claude`, `codex`, `gemini`, `copilot`,
  `opencode`, and `shell`. All build on a shared Ubuntu 26.04 base with
  Node.js 22, Docker Engine, `uv`, `gh`, and an unprivileged `sandbox`
  user with passwordless sudo. Each agent runs with its native
  yolo-equivalent flag (or permissive config for opencode), trusting the
  VM boundary instead of in-prompt approval.
- **Per-sandbox network proxy** (Swift NIO, SOCKS5 + HTTP CONNECT + plain
  HTTP forwarding) listening on a per-sandbox Unix socket shared into the
  VM via virtiofs. Inside the container, `proxy-bridge` (Go) listens on
  `127.0.0.1:3128` and forwards to that socket.
- **Network policy** with domain allowlist/blocklist, default-blocked
  CIDRs covering RFC1918 / link-local / IPv6 ULA, and runtime mutation
  via `container sandbox network proxy`. Policies persist in state
  storage and survive sandbox restarts.
- **Nested Docker** support inside agent containers. `dockerd` is
  configured to use `127.0.0.1:3128` for image pulls, and nested
  containers reach the proxy bridge via the docker bridge gateway
  (`172.17.0.1:3128`).
- **Session tracking** with auto-stop when the last interactive session
  exits, backed by host-side PID files.
- **Deterministic sandbox naming** — agent + SHA-256 prefix of the
  workspace path — so `container sandbox run claude .` from the same
  directory always reuses the same sandbox.
- **Workspace mounts** via virtiofs with `:ro` annotation support and
  multiple extra workspaces per sandbox.
- **`container sandbox save`** to snapshot a sandbox to an image archive.
- **`--version`** flag on the root command.
- **CI** (GitHub Actions, macos-26): swift format lint + 305 hermetic
  tests across 45 suites, with SwiftPM artifact and `.build` caching
  keyed on Xcode build + `Package.resolved`.
- **Release packaging** via `make package VERSION=v...`: codesigned,
  optionally notarized tarball with stable layout for downstream
  packagers.

### Architecture notes

- Swift 6.2, strict concurrency throughout
- Apple Container 0.12.1 (pinned to next minor)
- Linux helpers (`sandbox-init`, `proxy-bridge`) cross-compiled from a
  Go 1.23 module under `init-image/`
- Code style follows apple/container's `.swift-format` config

### Known limitations

- Apple Container is pre-1.0; minor version bumps may break us.
- OpenCode template uses a wildcard-allow permission config rather than
  a CLI flag (no global yolo flag exists on opencode yet).
- Shell template inherits the full agent base image (Node + Docker), so
  it's heavier than a minimal Ubuntu shell.

[Unreleased]: https://github.com/echthesia/container-sandbox/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/echthesia/container-sandbox/releases/tag/v0.1.0
