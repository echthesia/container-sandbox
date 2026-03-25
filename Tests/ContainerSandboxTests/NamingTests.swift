import Testing
@testable import sandbox

@Suite("SandboxNaming")
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
}
