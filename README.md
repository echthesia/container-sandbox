# container-sandbox

A Swift CLI plugin for [Apple's Container framework](https://github.com/apple/container) that creates isolated sandbox environments for AI coding agents. Installs as a `container` subcommand:

```
container sandbox run claude
```

Each sandbox is a Linux VM with the agent installed, a per-sandbox HTTP/SOCKS5 proxy enforcing a configurable network policy, and the host workspace mounted in via virtiofs. All agent templates share a common base image with Node.js, Docker Engine (for nested containers), `uv`, `gh`, and an unprivileged `sandbox` user with passwordless sudo.

> **Not affiliated with Apple.** This is a community plugin built on top of Apple's open-source [`container`](https://github.com/apple/container) framework.

## Requirements

- macOS 26 or later (Apple Silicon)
- [Apple Container](https://github.com/apple/container) ≥ 0.11.0, installed via Homebrew (`brew install container`)
- Xcode 26 / Swift 6.2 toolchain
- Go 1.23+ (only needed to cross-compile the in-container helpers under `init-image/`; `make install` runs this for you)

For development:

- `swift format` — bundled with the Swift 6 toolchain, no separate install. Config (`.swift-format`) matches upstream apple/container. `make verify` runs `swift format lint --strict` + tests; `make format` applies in place. The post-write hook in `.claude/settings.json` auto-formats Swift files on edit.

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

All templates build on a shared Ubuntu 26.04 base (Node.js 22, Docker Engine, [`uv`](https://github.com/astral-sh/uv), `gh`, `git`, sudo-enabled `sandbox` user) and run with the agent's own "yolo"-equivalent flag — every template trusts the VM boundary instead of in-prompt approval.

| Agent | Install | Yolo flag | Auth env |
|---|---|---|---|
| **claude** | [Claude Code](https://claude.com/claude-code) install script | `--dangerously-skip-permissions` | `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, AWS/Bedrock/Vertex |
| **codex** | `npm i -g @openai/codex` | `--dangerously-bypass-approvals-and-sandbox` | `OPENAI_API_KEY` |
| **gemini** | `npm i -g @google/gemini-cli` | `--yolo` | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_CLOUD_PROJECT` |
| **copilot** | `npm i -g @github/copilot` | `--yolo` | `GITHUB_TOKEN` / `GH_TOKEN` / `COPILOT_GITHUB_TOKEN` |
| **opencode** | [opencode.ai](https://opencode.ai) install script + permissive config | (config-based: `permission: { "*": "allow" }`) | provider keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`) |
| **shell** | none — bash on the shared base | n/a | none |

To add another agent, conform to `AgentTemplate` in `Sources/ContainerSandbox/Agent/` and register it in `AgentRegistry`.

## Networking

Each sandbox gets its own `ProxyServer` (Swift NIO, SOCKS5 + HTTP CONNECT) running on the host, listening on a per-sandbox Unix socket shared into the VM via virtiofs. Inside the container, `proxy-bridge` (Go) listens on `127.0.0.1:3128` and forwards to that socket; the agent's traffic is filtered against the policy before leaving the host.

Policies are domain-allowlist or blocklist, with default-blocked CIDRs that cover RFC1918, link-local, and IPv6 ULA/link-local ranges. All built-in templates currently default to allow-all; tighten per sandbox at runtime with `container sandbox network proxy`.

Nested Docker pulls also flow through the proxy: `dockerd` is configured to use `http://127.0.0.1:3128`, and nested containers reach `proxy-bridge` via the docker bridge gateway (`172.17.0.1:3128`).

## Threat model

The Claude template runs Claude Code with `--dangerously-skip-permissions`. Trust boundaries are:

- **Host workspace** — mounted via virtiofs; the agent has full read/write inside whatever directories you pass on the command line. Pass `:ro` to mount read-only.
- **Host filesystem outside the workspace** — not accessible. The init process and proxy run inside the VM.
- **Network egress** — gated by the per-sandbox proxy. Default-blocked CIDRs prevent reaching host loopback or RFC1918 networks even on allow-all policies.
- **Host secrets** — only the env vars listed in the template's `passthroughEnvironment` cross the boundary (e.g. `ANTHROPIC_API_KEY`). Anything else stays on the host.

This is a sandbox, not an air gap. An agent inside can still consume API quota, push to git remotes you've passed credentials for, and reach any host you've allowlisted. Treat the network policy as the security control.

## Development

```sh
make build        # release build of the Swift CLI
make verify       # swift format lint --strict + swift test
make format       # apply swift format in place
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
