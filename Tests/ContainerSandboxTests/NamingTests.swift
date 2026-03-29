@testable import sandbox
import Testing

struct NamingTests {
    @Test func includesDirnameAndHash() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        #expect(name.hasPrefix("sandbox-claude-my-project-"))
        #expect(name.count > "sandbox-claude-my-project-".count)
    }

    @Test func isDeterministic() {
        let a = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        let b = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        #expect(a == b)
    }

    @Test func differsByFullPath() {
        let a = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        let b = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/other/Code/my-project")
        #expect(a != b)
        // Both start with the same dirname prefix
        #expect(a.hasPrefix("sandbox-claude-my-project-"))
        #expect(b.hasPrefix("sandbox-claude-my-project-"))
    }

    @Test func lowercasesDirname() {
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/MyProject")
        #expect(name.contains("-myproject-"))
    }

    @Test func sanitizesSpecialCharacters() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my project (copy)")
        #expect(name.contains("-myprojectcopy-"))
    }

    @Test func preservesHyphensUnderscoresPeriods() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project_v2.0")
        #expect(name.contains("-my-project_v2.0-"))
    }

    @Test func isSandboxNameMatchesPrefix() {
        #expect(SandboxNaming.isSandboxName("sandbox-claude-myproject-abcd1234"))
        #expect(SandboxNaming.isSandboxName("sandbox-shell-foo-1234abcd"))
        #expect(!SandboxNaming.isSandboxName("buildkit"))
        #expect(!SandboxNaming.isSandboxName("my-container"))
        #expect(!SandboxNaming.isSandboxName(""))
    }

    @Test func isSandboxNameMinimalPrefix() {
        // "sandbox-" is the bare minimum that matches the prefix check
        #expect(SandboxNaming.isSandboxName("sandbox-"))
        // But does it represent a valid sandbox? Probably not.
    }

    // MARK: - Adversarial: path edge cases

    @Test func rootPathProducesValidName() {
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/")
        #expect(name.hasPrefix("sandbox-shell-"))
        #expect(!name.isEmpty)
        // lastPathComponent of "/" might be "/" which sanitizes to "workspace"
        #expect(name.contains("workspace"))
    }

    @Test func pathWithOnlySpecialCharsUsesWorkspaceFallback() {
        // A dirname of only spaces/parens should sanitize to empty → "workspace"
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/   ")
        #expect(name.contains("workspace"))
    }

    @Test func unicodeDirectoryNamePreserved() {
        // CharacterSet.alphanumerics includes Unicode, so "café" should be preserved
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/café")
        #expect(name.contains("café"))
    }

    @Test func veryLongDirectoryNameTruncated() {
        let longDir = String(repeating: "a", count: 500)
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/\(longDir)")
        // Dirname portion is truncated to keep the full name under NAME_MAX (255)
        let truncated = String(repeating: "a", count: 64)
        #expect(name.contains("-\(truncated)-"))
        #expect(!name.contains(longDir))
        // Full name should be well under 255 characters
        #expect(name.count < 255)
    }

    @Test func hashCollisionResistance() {
        // Generate many names with same basename but different parent paths
        // and verify no hash collisions in the batch
        var hashes = Set<String>()
        for i in 0 ..< 1000 {
            let hash = SandboxNaming.shortHash("/path/\(i)/project")
            hashes.insert(hash)
        }
        #expect(hashes.count == 1000, "Found hash collision in 1000 distinct paths")
    }
}
