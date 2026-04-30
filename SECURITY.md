# Security Policy

`container-sandbox` is a security tool: it runs untrusted AI coding agents
inside isolated microVMs with a per-sandbox network proxy as the egress gate.
If you find a way to break that isolation, please report it privately so it
can be fixed before disclosure.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**https://github.com/echthesia/container-sandbox/security/advisories/new**

If GitHub is unavailable or you'd prefer email, contact
melissaemilyfoster@gmail.com with subject `[container-sandbox security]`.
PGP encryption is not currently set up — for highly sensitive reports, ask
in your initial message and a key will be provided.

Please include:

- A description of the issue and its impact
- Reproduction steps (commands, sandbox config, network policy used)
- Affected versions, if known
- Whether you've shared the report elsewhere

You should expect an acknowledgement within a few business days and a
substantive response within two weeks. Embargoed disclosure timelines are
negotiable based on severity and patch complexity.

## In scope

- Sandbox-escape vulnerabilities (agent code reaching the host filesystem,
  host network outside the proxy allowlist, or other host resources)
- Network policy bypasses in the per-sandbox proxy (SOCKS5, HTTP CONNECT,
  plain HTTP, CIDR enforcement)
- Privilege escalation between the unprivileged `sandbox` user and host
- Token/secret leakage through `passthroughEnvironment`, container labels,
  or proxy logs
- Supply-chain concerns in the container build (base image, agent install
  scripts, vendored binaries)

## Out of scope

- Issues in upstream dependencies (apple/container, swift-nio,
  swift-argument-parser, agent CLIs themselves) — please report those
  upstream. Cross-cutting integration issues that involve our usage are
  in scope.
- Misconfiguration of network policies by the operator (e.g. setting an
  allow-all policy on a sandbox running untrusted agents)
- Resource exhaustion within a single sandbox (CPU, memory, disk inside
  the VM) — the VM boundary is the design target
- Issues in the agent prompts themselves, including prompt injection that
  reaches sandbox-allowed network destinations

## Trust model recap

The README's "Threat model" section is the authoritative reference.
Briefly: the VM boundary and the per-sandbox proxy are the security
controls. Anything an agent can do *within* its allowlisted hosts and
mounted workspace is by design — including consuming API quota, pushing
to git remotes you've authorized, or running arbitrary code inside the
VM's filesystem.
