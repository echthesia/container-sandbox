import CryptoKit
import Foundation

enum SandboxNaming {
    static let prefix = "sandbox"

    private static let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))

    /// Generate a sandbox name from agent + full workspace path.
    /// Includes a short hash of the full path to avoid collisions when
    /// different directories share the same basename.
    static func sandboxName(agent: String, workspacePath: String) -> String {
        let url = URL(fileURLWithPath: workspacePath).standardized
        let dirname = sanitize(url.lastPathComponent)
        let hash = shortHash(url.path)
        return "\(prefix)-\(agent)-\(dirname)-\(hash)"
    }

    static func isSandboxName(_ id: String) -> Bool {
        id.hasPrefix("\(prefix)-")
    }

    /// Extract the agent name from a sandbox ID, if possible.
    static func agentName(from sandboxId: String) -> String? {
        let parts = sandboxId.split(separator: "-", maxSplits: 2)
        guard parts.count >= 2, parts[0] == prefix else { return nil }
        return String(parts[1])
    }

    private static func sanitize(_ name: String) -> String {
        let sanitized = name.unicodeScalars.filter { allowedCharacters.contains($0) }
        let result = String(String.UnicodeScalarView(sanitized))
        return result.isEmpty ? "workspace" : result.lowercased()
    }

    static func shortHash(_ path: String) -> String {
        let hash = SHA256.hash(data: Data(path.utf8))
        return hash.prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
