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

    @Test func extractsAgentName() {
        #expect(SandboxNaming.agentName(from: "sandbox-claude-myproject-abcd1234") == "claude")
        #expect(SandboxNaming.agentName(from: "sandbox-shell-foo-1234abcd") == "shell")
        #expect(SandboxNaming.agentName(from: "not-a-sandbox") == nil)
        #expect(SandboxNaming.agentName(from: "") == nil)
    }

    // MARK: - Adversarial: agent name extraction

    @Test func hyphenatedAgentNameExtraction() {
        // Agent name "my-agent" produces sandbox name "sandbox-my-agent-foo-hash"
        // But split(separator: "-", maxSplits: 2) gives ["sandbox", "my", "agent-foo-hash"]
        // So agentName extracts "my" instead of "my-agent"
        let name = SandboxNaming.sandboxName(agent: "my-agent", workspacePath: "/foo/bar")
        let extracted = SandboxNaming.agentName(from: name)
        #expect(extracted == "my-agent")
    }

    @Test func agentNameFromMinimalSandboxId() {
        // "sandbox-" with nothing after the second part
        let extracted = SandboxNaming.agentName(from: "sandbox-")
        // split gives ["sandbox", ""], parts[1] is "" — should return nil for empty agent
        #expect(extracted == nil)
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

    @Test func veryLongDirectoryName() {
        let longDir = String(repeating: "a", count: 500)
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/\(longDir)")
        // Should not crash, name includes the full (long) dirname
        #expect(name.contains(longDir.lowercased()))
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
