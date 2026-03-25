import Testing
@testable import sandbox

@Suite("SandboxNaming")
struct NamingTests {
    @Test func generatesNameFromAgentAndDirname() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        #expect(name == "sandbox-claude-my-project")
    }

    @Test func lowercasesDirname() {
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/MyProject")
        #expect(name == "sandbox-shell-myproject")
    }

    @Test func sanitizesSpecialCharacters() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my project (copy)")
        #expect(name == "sandbox-claude-myprojectcopy")
    }

    @Test func preservesHyphensUnderscoresPeriods() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project_v2.0")
        #expect(name == "sandbox-claude-my-project_v2.0")
    }

    @Test func emptyDirnameBecomesWorkspace() {
        // Edge case: root path
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/")
        #expect(name == "sandbox-claude-workspace")
    }

    @Test func isSandboxNameMatchesPrefix() {
        #expect(SandboxNaming.isSandboxName("sandbox-claude-myproject"))
        #expect(SandboxNaming.isSandboxName("sandbox-shell-foo"))
        #expect(!SandboxNaming.isSandboxName("buildkit"))
        #expect(!SandboxNaming.isSandboxName("my-container"))
        #expect(!SandboxNaming.isSandboxName(""))
    }

    @Test func extractsAgentName() {
        #expect(SandboxNaming.agentName(from: "sandbox-claude-myproject") == "claude")
        #expect(SandboxNaming.agentName(from: "sandbox-shell-foo") == "shell")
        #expect(SandboxNaming.agentName(from: "not-a-sandbox") == nil)
        #expect(SandboxNaming.agentName(from: "") == nil)
    }

    @Test func disambiguateAppendsHash() {
        let name = SandboxNaming.disambiguate(baseName: "sandbox-claude-myproject", workspacePath: "/Users/me/Code/myproject")
        #expect(name.hasPrefix("sandbox-claude-myproject-"))
        #expect(name.count > "sandbox-claude-myproject-".count)
    }

    @Test func disambiguateIsDeterministic() {
        let a = SandboxNaming.disambiguate(baseName: "sandbox-claude-myproject", workspacePath: "/Users/me/Code/myproject")
        let b = SandboxNaming.disambiguate(baseName: "sandbox-claude-myproject", workspacePath: "/Users/me/Code/myproject")
        #expect(a == b)
    }

    @Test func disambiguateDiffersForDifferentPaths() {
        let a = SandboxNaming.disambiguate(baseName: "sandbox-claude-myproject", workspacePath: "/Users/me/Code/myproject")
        let b = SandboxNaming.disambiguate(baseName: "sandbox-claude-myproject", workspacePath: "/Users/other/Code/myproject")
        #expect(a != b)
    }
}
