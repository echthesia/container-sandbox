import ContainerResource
import Foundation
import Testing

@testable import sandbox

struct RegistryTests {
    @Test func resolvesKnownAgents() {
        #expect(AgentRegistry.resolve("claude") != nil)
        #expect(AgentRegistry.resolve("shell") != nil)
    }

    @Test func returnsNilForUnknown() {
        #expect(AgentRegistry.resolve("nonexistent") == nil)
        #expect(AgentRegistry.resolve("") == nil)
    }

    @Test func listsAvailableAgents() {
        let agents = AgentRegistry.availableAgents
        #expect(agents.contains("claude"))
        #expect(agents.contains("shell"))
        #expect(agents == agents.sorted())
    }
}

struct ClaudeTemplateTests {
    let template = ClaudeTemplate()

    @Test func hasContainerfile() throws {
        let content = try #require(template.containerfileContent)
        #expect(content.contains("ubuntu:26.04"))
        #expect(content.contains("claude.ai/install.sh"))
        #expect(content.contains("sandbox"))
    }

    @Test func passesThroughAPIKeys() {
        #expect(template.passthroughEnvironment.contains("ANTHROPIC_API_KEY"))
        #expect(template.passthroughEnvironment.contains("CLAUDE_CODE_OAUTH_TOKEN"))
    }
}
