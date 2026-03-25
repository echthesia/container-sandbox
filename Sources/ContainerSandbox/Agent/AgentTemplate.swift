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
    var containerfileContent: String? { nil }
    var defaultNetworkPolicy: NetworkPolicy { .full }
}

extension AgentTemplate {
    /// Build a ProcessConfiguration for this agent's entrypoint.
    /// The `baseConfig` is the container's init process config — we inherit user and base env from it.
    func processConfiguration(
        baseConfig: ProcessConfiguration,
        workingDirectory: String,
        extraArgs: [String] = [],
        extraEnv: [String: String] = [:],
        proxyAddress: String? = nil
    ) -> ProcessConfiguration {
        // Layer env with last-writer-wins deduplication on key.
        // Order: image defaults < template defaults < host passthrough < caller extras
        var envMap: [(key: String, value: String)] = []

        for entry in baseConfig.environment {
            let (k, v) = Self.splitEnvEntry(entry)
            envMap.append((k, v))
        }
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
        if let proxyAddress {
            envMap.append(("HTTP_PROXY", "http://\(proxyAddress)"))
            envMap.append(("HTTPS_PROXY", "http://\(proxyAddress)"))
            envMap.append(("NO_PROXY", "localhost,127.0.0.1"))
        }

        // Deduplicate: keep last occurrence of each key
        var seen = Set<String>()
        var env: [String] = []
        for (key, value) in envMap.reversed() {
            if seen.insert(key).inserted {
                env.append("\(key)=\(value)")
            }
        }
        env.reverse()

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

    private static func splitEnvEntry(_ entry: String) -> (key: String, value: String) {
        let parts = entry.split(separator: "=", maxSplits: 1)
        if parts.count == 2 {
            return (String(parts[0]), String(parts[1]))
        }
        return (entry, "")
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
