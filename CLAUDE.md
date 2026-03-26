# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A Swift CLI plugin for Apple's Container framework that creates isolated sandbox environments for AI coding agents. Installed as a `container` subcommand (`container sandbox ...`).

- macOS 15+, Swift 6.2, strict concurrency (`Sendable` throughout)
- Depends on `apple/container` (0.10.0) and `swift-argument-parser`

## Build / Test / Install

```
make build          # swift build -c release
make install        # build + copy + codesign + symlink into container plugin dir
make clean          # swift package clean
swift test          # run tests (native Swift testing framework)
```

The binary **must be codesigned** after copying (`codesign -fs -`). `make install` handles this; if you manually copy the binary, codesign it yourself.

## Architecture

- `Sources/ContainerSandbox/CLI/` — ArgumentParser commands (`run`, `create`, `exec`, `list`, `stop`, `remove`, `save`)
- `Sources/ContainerSandbox/Sandbox/` — `SandboxManager` (container lifecycle via ContainerClient), `SessionTracker` (auto-stop on last session exit), naming utilities
- `Sources/ContainerSandbox/Agent/` — `AgentTemplate` protocol + registry; `ClaudeTemplate`, `ShellTemplate`
- `Containerfiles/claude/` — Ubuntu 24.04 image with Claude Code, Node.js 22, uv, podman

## Key patterns

- **Environment layering**: image env < template env < host passthrough < caller extras (last-writer-wins dedup)
- **Deterministic naming**: sandbox names include SHA256(workspace path) prefix to avoid collisions
- **Session tracking**: host-side PID files in `~/.local/state/container-sandbox/sessions/`
- **Init process**: containers run `/bin/sleep infinity` as PID 1; agents run via `exec`

## Container API

The Apple Container API docs are JS-rendered DoCC — they cannot be fetched or read directly. When you need API details, **read the source code** from the `apple/container` package (in `.build/checkouts/container/`) rather than trying to fetch documentation URLs.
