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
        let agentPart = sanitize(agent)
        let dirname = sanitize(url.lastPathComponent)
        let hash = shortHash(url.path)
        return "\(prefix)-\(agentPart)-\(dirname)-\(hash)"
    }

    static func isSandboxName(_ id: String) -> Bool {
        id.hasPrefix("\(prefix)-")
    }

    /// Validate that a name is safe to use as a directory component for state storage.
    static func validateName(_ name: String) throws {
        guard !name.isEmpty, name != ".", !name.contains("/"), !name.contains("..") else {
            throw SandboxError.invalidName(name)
        }
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
