import Foundation

/// User configuration loaded from ~/.config/container-sandbox/config.json.
///
/// Format:
/// ```json
/// {
///   "env": { "KEY": "value" },
///   "agents": {
///     "claude": { "env": { "KEY": "value" } }
///   }
/// }
/// ```
struct UserConfig: Codable {
    var env: [String: String]?
    var agents: [String: AgentConfig]?

    struct AgentConfig: Codable {
        var env: [String: String]?
    }

    /// Resolve environment for a given agent. Shared env merged with agent-specific,
    /// agent wins on conflicts.
    func environment(for agent: String) -> [String: String] {
        var result = env ?? [:]
        if let agentEnv = agents?[agent]?.env {
            result.merge(agentEnv) { _, agent in agent }
        }
        return result
    }

    /// Default config file path.
    static let defaultPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".config/container-sandbox/config.json").path

    /// Load from disk. Returns empty config if the file doesn't exist.
    static func load(from path: String = defaultPath) -> UserConfig {
        guard let data = FileManager.default.contents(atPath: path) else {
            return UserConfig()
        }
        do {
            return try JSONDecoder().decode(UserConfig.self, from: data)
        } catch {
            // Don't crash on malformed config — log and continue with empty config.
            return UserConfig()
        }
    }
}
