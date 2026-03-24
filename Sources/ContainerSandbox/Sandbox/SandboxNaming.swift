import CryptoKit
import Foundation

enum SandboxNaming {
    static let prefix = "sandbox"

    /// Generate a sandbox name from agent + workspace path.
    /// Format: "sandbox-{agent}-{dirname}" or "sandbox-{agent}-{dirname}-{hash4}" if collision.
    static func sandboxName(agent: String, workspacePath: String) -> String {
        let resolved = URL(fileURLWithPath: workspacePath).standardized.path
        let dirname = sanitize(URL(fileURLWithPath: resolved).lastPathComponent)
        return "\(prefix)-\(agent)-\(dirname)"
    }

    /// Check if a container ID looks like a sandbox we manage.
    static func isSandboxName(_ id: String) -> Bool {
        id.hasPrefix("\(prefix)-")
    }

    /// Extract the agent name from a sandbox ID, if possible.
    static func agentName(from sandboxId: String) -> String? {
        let parts = sandboxId.split(separator: "-", maxSplits: 2)
        guard parts.count >= 2, parts[0] == prefix else { return nil }
        return String(parts[1])
    }

    /// Sanitize a directory name for use in a container ID.
    /// Keeps alphanumeric, hyphens, underscores, periods.
    private static func sanitize(_ name: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        let sanitized = name.unicodeScalars.filter { allowed.contains($0) }
        let result = String(String.UnicodeScalarView(sanitized))
        return result.isEmpty ? "workspace" : result.lowercased()
    }

    /// Append a short hash to disambiguate collisions.
    static func disambiguate(baseName: String, workspacePath: String) -> String {
        let resolved = URL(fileURLWithPath: workspacePath).standardized.path
        let hash = SHA256.hash(data: Data(resolved.utf8))
        let shortHash = hash.prefix(2).map { String(format: "%02x", $0) }.joined()
        return "\(baseName)-\(shortHash)"
    }
}
