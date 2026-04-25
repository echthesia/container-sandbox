# container-sandbox

A Swift CLI plugin for [Apple's Container framework](https://github.com/apple/container) that creates isolated sandbox environments for AI coding agents. Installs as a `container` subcommand:

```
container sandbox run claude
```

Each sandbox is a Linux VM with the agent installed, a per-sandbox HTTP/SOCKS5 proxy enforcing a configurable network policy, and the host workspace mounted in via virtiofs. Nested Docker is supported inside the Claude template.

> **Not affiliated with Apple.** This is a community plugin built on top of Apple's open-source [`container`](https://github.com/apple/container) framework.

## Requirements

- macOS 26 or later (Apple Silicon)
- [Apple Container](https://github.com/apple/container) ≥ 0.11.0, installed via Homebrew (`brew install container`)
- Xcode 26 / Swift 6.2 toolchain
- Go 1.23+ (only needed to cross-compile the in-container helpers under `init-image/`; `make install` runs this for you)

For development:

- [SwiftLint](https://github.com/realm/SwiftLint) (`brew install swiftlint`) — `make verify` runs lint + tests
- [SwiftFormat](https://github.com/nicklockwood/SwiftFormat) (`brew install swiftformat`) — used by the post-write hook in `.claude/settings.json` to auto-format on edit

## Install

```sh
git clone <this repo>
cd ac-agent-sandbox
make install
```

This builds the Swift CLI in release mode, codesigns it, cross-compiles the Linux init helpers, and symlinks `$(brew --prefix container)/libexec/container-plugins/sandbox` to a stable location under `~/.local/lib/container-sandbox/`. After install, `container sandbox --help` should work.

To remove: `make uninstall`.

## Usage

```
container sandbox run    [<agent>] [<workspace>]   # run an agent (default: claude)
container sandbox create  <agent>   <workspace>    # create without starting
container sandbox exec    <name>   -- <command>    # exec inside a running sandbox
container sandbox ls                               # list sandboxes
container sandbox stop    <name>...                # stop sandboxes
container sandbox rm      <name>...                # remove sandboxes
container sandbox save    <name>    <archive>      # snapshot to an image archive
container sandbox network proxy ...                # inspect or change a sandbox's network policy
container sandbox network log ...                  # tail proxy decisions
```

Sandbox names are deterministic — the agent name plus a SHA-256 prefix of the workspace path — so `container sandbox run claude .` from the same directory always reuses the same sandbox.

### Built-in agent templates

- **claude** — Ubuntu 26.04, [Claude Code](https://claude.com/claude-code) installed under `/home/sandbox/.local`, [`uv`](https://github.com/astral-sh/uv) vendored in, Docker Engine for nested containers, sudo access for the `sandbox` user.
- **shell** — minimal interactive shell sandbox.

To add another agent, conform to `AgentTemplate` in `Sources/ContainerSandbox/Agent/` and register it.

## Networking

Each sandbox gets its own `ProxyServer` (Swift NIO, SOCKS5 + HTTP CONNECT) running on the host, listening on a per-sandbox Unix socket shared into the VM via virtiofs. Inside the container, `proxy-bridge` (Go) listens on `127.0.0.1:3128` and forwards to that socket; the agent's traffic is filtered against the policy before leaving the host.

Policies are domain-allowlist or blocklist, with default-blocked CIDRs that cover RFC1918, link-local, and IPv6 ULA/link-local ranges. The `claude` template defaults to allow-all; the `shell` template defaults to deny-all. Inspect or change at runtime with `container sandbox network proxy`.

Nested Docker pulls also flow through the proxy: `dockerd` is configured to use `http://127.0.0.1:3128`, and nested containers reach `proxy-bridge` via the docker bridge gateway (`172.17.0.1:3128`).

## Threat model

The Claude template runs Claude Code with `--dangerously-skip-permissions` — that's the **point** of the sandbox. Trust boundaries are:

- **Host workspace** — mounted via virtiofs; the agent has full read/write inside whatever directories you pass on the command line. Pass `:ro` to mount read-only.
- **Host filesystem outside the workspace** — not accessible. The init process and proxy run inside the VM.
- **Network egress** — gated by the per-sandbox proxy. Default-blocked CIDRs prevent reaching host loopback or RFC1918 networks even on allow-all policies.
- **Host secrets** — only the env vars listed in the template's `passthroughEnvironment` cross the boundary (e.g. `ANTHROPIC_API_KEY`). Anything else stays on the host.

This is a sandbox, not an air gap. An agent inside can still consume API quota, push to git remotes you've passed credentials for, and reach any host you've allowlisted. Treat the network policy as the security control.

## Development

```sh
make build        # release build of the Swift CLI
make verify       # swiftlint (advisory) + swift test
make init-binaries # cross-compile the Go helpers for Linux
swift test        # native Swift Testing framework, hermetic
```

Source layout:

- `Sources/ContainerSandbox/CLI/` — ArgumentParser command tree
- `Sources/ContainerSandbox/Sandbox/` — container lifecycle, session tracking, naming
- `Sources/ContainerSandbox/Agent/` — agent template protocol + built-in templates
- `Sources/ContainerSandbox/Network/` — proxy server, network policy, domain filter
- `Sources/ContainerSandbox/Utilities/` — shared helpers
- `init-image/` — Go module for `sandbox-init` (PID 2 under vminitd) and `proxy-bridge` (TCP↔UDS relay)
- `Tests/ContainerSandboxTests/` — Swift Testing suites; tests are hermetic and run in parallel

See [CLAUDE.md](CLAUDE.md) for further notes on architecture and conventions.

## License

[Apache License 2.0](LICENSE).
