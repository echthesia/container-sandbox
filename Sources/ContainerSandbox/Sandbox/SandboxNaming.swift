import CryptoKit
import Foundation

enum SandboxNaming {
    static let prefix = "sandbox"

    private static let allowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")

    /// Maximum length of the full sandbox name. The name is used as the
    /// container id, and the host→guest socket relay binds at
    /// `/run/container/<id>/sockets/<UUID>.sock` inside the guest. The fixed
    /// portion of that path is 65 bytes, and Linux's `sun_path` limit is 108
    /// (strict <), leaving 42 bytes for `<id>`. Names longer than this would
    /// fail at relay-bind time, not at create time.
    static let maxNameLength = 42

    /// Hard cap on the agent segment, regardless of budget. In practice agents
    /// are short ("claude", "shell"); this just defends against pathological
    /// input so the dirname segment can't be squeezed out entirely.
    private static let maxAgentLength = 16

    /// Generate a sandbox name from agent + full workspace path.
    /// Includes a short hash of the full path to avoid collisions when
    /// different directories share the same basename. The dirname segment
    /// is truncated as needed so the full name fits within `maxNameLength`.
    static func sandboxName(agent: String, workspacePath: String) -> String {
        let url = URL(fileURLWithPath: workspacePath).standardized
        let agentPart = sanitize(agent, max: maxAgentLength)
        let hash = shortHash(url.path)
        // Layout: "sandbox-<agent>-<dirname>-<hash>"
        let fixed = prefix.count + 1 + agentPart.count + 1 + 1 + hash.count
        let dirnameBudget = max(0, maxNameLength - fixed)
        let dirname = sanitize(url.lastPathComponent, max: dirnameBudget)
        return "\(prefix)-\(agentPart)-\(dirname)-\(hash)"
    }

    static func isSandboxName(_ id: String) -> Bool {
        id.hasPrefix("\(prefix)-")
    }

    /// Validate that a name is safe to use as a directory component for state
    /// storage and short enough to fit within the relay-bind limit.
    static func validateName(_ name: String) throws {
        guard !name.isEmpty, name != ".", !name.contains("/"), !name.contains("..") else {
            throw SandboxError.invalidName(name)
        }
        guard name.utf8.count <= maxNameLength else {
            throw SandboxError.nameTooLong(name: name, limit: maxNameLength)
        }
        if AgentRegistry.resolve(name) != nil {
            throw SandboxError.reservedName(name)
        }
    }

    private static func sanitize(_ name: String, max maxLength: Int) -> String {
        guard maxLength > 0 else { return "" }
        let sanitized = name.unicodeScalars.filter { allowedCharacters.contains($0) }
        var result = String(String.UnicodeScalarView(sanitized))
        if result.count > maxLength {
            result = String(result.prefix(maxLength))
        }
        if result.isEmpty {
            return String("workspace".prefix(maxLength))
        }
        return result.lowercased()
    }

    static func shortHash(_ path: String) -> String {
        let hash = SHA256.hash(data: Data(path.utf8))
        return hash.prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
