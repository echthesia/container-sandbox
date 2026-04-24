import CryptoKit
import Foundation

enum SandboxNaming {
    static let prefix = "sandbox"

    private static let allowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")

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
        if AgentRegistry.resolve(name) != nil {
            throw SandboxError.reservedName(name)
        }
    }

    /// Maximum length for the dirname portion of a sandbox name.
    /// Keeps the full name well under NAME_MAX (255) on APFS/HFS+.
    private static let maxDirnameLength = 64

    private static func sanitize(_ name: String) -> String {
        let sanitized = name.unicodeScalars.filter { allowedCharacters.contains($0) }
        var result = String(String.UnicodeScalarView(sanitized))
        if result.count > maxDirnameLength {
            result = String(result.prefix(maxDirnameLength))
        }
        return result.isEmpty ? "workspace" : result.lowercased()
    }

    static func shortHash(_ path: String) -> String {
        let hash = SHA256.hash(data: Data(path.utf8))
        return hash.prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
