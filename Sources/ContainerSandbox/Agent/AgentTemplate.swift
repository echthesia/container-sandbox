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
}

extension AgentTemplate {
    var containerfileContent: String? { nil }
}

extension AgentTemplate {
    /// Build a ProcessConfiguration for this agent's entrypoint.
    /// The `baseConfig` is the container's init process config — we inherit user and base env from it.
    func processConfiguration(
        baseConfig: ProcessConfiguration,
        workingDirectory: String,
        extraArgs: [String] = [],
        extraEnv: [String: String] = [:]
    ) -> ProcessConfiguration {
        // Start with the init process's environment (includes PATH, etc.)
        var env = baseConfig.environment

        // Merge template defaults
        for (key, value) in defaultEnvironment {
            env.append("\(key)=\(value)")
        }

        // Passthrough host env vars that are set
        for key in passthroughEnvironment {
            if let value = ProcessInfo.processInfo.environment[key] {
                env.append("\(key)=\(value)")
            }
        }

        // Extra env from caller
        for (key, value) in extraEnv {
            env.append("\(key)=\(value)")
        }

        var args = entrypoint
        if !extraArgs.isEmpty {
            args.append(contentsOf: extraArgs)
        }

        return ProcessConfiguration(
            executable: args[0],
            arguments: Array(args.dropFirst()),
            environment: env,
            workingDirectory: workingDirectory,
            terminal: true,
            user: baseConfig.user
        )
    }
}

enum AgentRegistry {
    private static let agents: [String: any AgentTemplate] = [
        "claude": ClaudeTemplate(),
        "shell": ShellTemplate(),
    ]

    static func resolve(_ name: String) -> (any AgentTemplate)? {
        agents[name]
    }

    static var availableAgents: [String] {
        agents.keys.sorted()
    }
}
