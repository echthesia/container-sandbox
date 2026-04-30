import ContainerAPIClient
import ContainerResource
import Foundation

/// Defines a sandbox agent configuration — image, entrypoint, env vars, etc.
protocol AgentTemplate: Sendable {
    var name: String { get }
    var defaultImage: String { get }
    /// Embedded Containerfile content for building the image. Nil means use the image as-is.
    var containerfileContent: String? { get }
    var entrypoint: [String] { get }
    var defaultEnvironment: [String: String] { get }
    var passthroughEnvironment: [String] { get }
    var requiresSSH: Bool { get }
    var requiresVirtualization: Bool { get }
    var useInit: Bool { get }
    var defaultNetworkPolicy: NetworkPolicy { get }
}

extension AgentTemplate {
    var containerfileContent: String? {
        nil
    }

    var defaultNetworkPolicy: NetworkPolicy {
        .allow
    }
}

extension AgentTemplate {
    /// Build a ProcessConfiguration for this agent's entrypoint.
    /// The `baseConfig` is the container's init process config — we inherit base env from it.
    /// `userOverride` lets callers specify the image user (since the init process runs as root).
    func processConfiguration(
        baseConfig: ProcessConfiguration,
        workingDirectory: String,
        extraArgs: [String] = [],
        extraEnv: [String: String] = [:],
        userOverride: ProcessConfiguration.User? = nil
    ) -> ProcessConfiguration {
        // Layer env with last-writer-wins deduplication on key.
        // Order: image defaults < TERM (if tty) < template defaults < host passthrough < caller extras
        var envMap: [(key: String, value: String)] = []

        for entry in baseConfig.environment {
            if let (k, v) = parseEnvEntry(entry) {
                envMap.append((k, v))
            }
        }
        // Inject TERM for TTY sessions, matching Docker's behavior.
        // Positioned before template defaults so templates can override.
        envMap.append(("TERM", "xterm-256color"))
        for (key, value) in defaultEnvironment {
            envMap.append((key, value))
        }
        for key in passthroughEnvironment {
            if let value = ProcessInfo.processInfo.environment[key] {
                envMap.append((key, value))
            }
        }
        for (key, value) in extraEnv {
            envMap.append((key, value))
        }
        // Proxy is always running on every sandbox.
        for entry in ProxyManager.proxyEnvironment {
            envMap.append(entry)
        }

        let env = deduplicateEnvironment(envMap)

        var args = entrypoint
        precondition(!args.isEmpty, "AgentTemplate.entrypoint must not be empty")
        if !extraArgs.isEmpty {
            args.append(contentsOf: extraArgs)
        }

        return ProcessConfiguration(
            executable: args[0],
            arguments: Array(args.dropFirst()),
            environment: env,
            workingDirectory: workingDirectory,
            terminal: true,
            user: userOverride ?? baseConfig.user
        )
    }
}

enum AgentRegistry {
    private static let agents: [String: any AgentTemplate] = [
        "claude": ClaudeTemplate(),
        "codex": CodexTemplate(),
        "copilot": CopilotTemplate(),
        "gemini": GeminiTemplate(),
        "opencode": OpenCodeTemplate(),
        "shell": ShellTemplate(),
    ]

    static func resolve(_ name: String) -> (any AgentTemplate)? {
        agents[name]
    }

    static var availableAgents: [String] {
        agents.keys.sorted()
    }
}
