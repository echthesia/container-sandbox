import ContainerResource
import Foundation
import Testing

@testable import sandbox

struct RegistryTests {
    @Test func resolvesKnownAgents() {
        for name in ["claude", "codex", "copilot", "gemini", "opencode", "shell"] {
            #expect(AgentRegistry.resolve(name) != nil, "missing agent: \(name)")
        }
    }

    @Test func returnsNilForUnknown() {
        #expect(AgentRegistry.resolve("nonexistent") == nil)
        #expect(AgentRegistry.resolve("") == nil)
    }

    @Test func availableAgentsIsSortedAndComplete() {
        let agents = AgentRegistry.availableAgents
        #expect(agents == agents.sorted())
        #expect(Set(agents) == ["claude", "codex", "copilot", "gemini", "opencode", "shell"])
    }
}

// MARK: - Cross-template invariants

/// Every registered template should satisfy these properties regardless of
/// which agent it installs. New templates are picked up automatically via
/// AgentRegistry.availableAgents.
struct TemplateInvariantTests {
    @Test(arguments: AgentRegistry.availableAgents)
    func entrypointIsAbsolute(_ name: String) throws {
        let template = try #require(AgentRegistry.resolve(name))
        #expect(!template.entrypoint.isEmpty, "\(name): entrypoint must not be empty")
        let executable = template.entrypoint[0]
        #expect(executable.hasPrefix("/"), "\(name): entrypoint executable must be absolute, got '\(executable)'")
    }

    @Test(arguments: AgentRegistry.availableAgents)
    func builtOnSharedBase(_ name: String) throws {
        let template = try #require(AgentRegistry.resolve(name))
        let content = try #require(
            template.containerfileContent,
            "\(name): every template should build from the shared base")
        #expect(content.contains("FROM docker.io/ubuntu:26.04"), "\(name): missing base image")
        #expect(content.contains("USER sandbox"), "\(name): base should switch to sandbox user")
        #expect(content.contains("NPM_CONFIG_PREFIX"), "\(name): base should configure npm prefix")
    }

    @Test func defaultImageTagsAreUnique() {
        let tags = AgentRegistry.availableAgents.compactMap { AgentRegistry.resolve($0)?.defaultImage }
        #expect(tags.count == AgentRegistry.availableAgents.count, "every agent should have an image tag")
        #expect(Set(tags).count == tags.count, "image tags must be unique across agents")
    }

    @Test(arguments: AgentRegistry.availableAgents)
    func sandboxUserCanFindEntrypoint(_ name: String) throws {
        // Entrypoint must be reachable by the sandbox user — either an absolute
        // path under /home/sandbox/.local, /home/sandbox/.opencode, or a system
        // binary under /bin or /usr/bin. Catches typos and relocations.
        let template = try #require(AgentRegistry.resolve(name))
        let executable = template.entrypoint[0]
        let validPrefixes = ["/home/sandbox/", "/bin/", "/usr/bin/", "/usr/local/bin/"]
        #expect(
            validPrefixes.contains(where: { executable.hasPrefix($0) }),
            "\(name): entrypoint '\(executable)' is not in a known location")
    }
}

// MARK: - Per-template install markers

/// Each agent's containerfile should contain the canonical install command for
/// that agent. If an upstream package gets renamed or the install URL moves,
/// these tests fail loudly so the template can be updated together.
struct TemplateInstallMarkerTests {
    @Test(arguments: [
        ("claude", "claude.ai/install.sh"),
        ("codex", "npm install -g @openai/codex"),
        ("copilot", "npm install -g @github/copilot"),
        ("gemini", "npm install -g @google/gemini-cli"),
        ("opencode", "opencode.ai/install"),
    ])
    func containerfileInstallsExpectedAgent(_ name: String, _ marker: String) throws {
        let template = try #require(AgentRegistry.resolve(name))
        let content = try #require(template.containerfileContent)
        #expect(
            content.contains(marker),
            "\(name): containerfile should contain install marker '\(marker)'")
    }
}

// MARK: - Claude-specific assertions

struct ClaudeTemplateTests {
    let template = ClaudeTemplate()

    @Test func passesThroughAPIKeys() {
        for key in ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"] {
            #expect(template.passthroughEnvironment.contains(key), "missing passthrough: \(key)")
        }
    }
}
