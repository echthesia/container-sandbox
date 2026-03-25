import Foundation
import Testing
@testable import sandbox

@Suite("AgentRegistry")
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
        #expect(agents == agents.sorted()) // should be sorted
    }
}

@Suite("ClaudeTemplate")
struct ClaudeTemplateTests {
    let template = ClaudeTemplate()

    @Test func hasCorrectName() {
        #expect(template.name == "claude")
    }

    @Test func hasContainerfile() {
        #expect(template.containerfileContent != nil)
        #expect(template.containerfileContent!.contains("ubuntu:24.04"))
        #expect(template.containerfileContent!.contains("claude.ai/install.sh"))
        #expect(template.containerfileContent!.contains("sandbox"))
    }

    @Test func passesThroughAPIKeys() {
        #expect(template.passthroughEnvironment.contains("ANTHROPIC_API_KEY"))
        #expect(template.passthroughEnvironment.contains("CLAUDE_CODE_OAUTH_TOKEN"))
    }

    @Test func requiresSSH() {
        #expect(template.requiresSSH)
    }

    @Test func doesNotRequireVirtualization() {
        #expect(!template.requiresVirtualization)
    }
}

@Suite("ShellTemplate")
struct ShellTemplateTests {
    let template = ShellTemplate()

    @Test func hasCorrectName() {
        #expect(template.name == "shell")
    }

    @Test func hasNoContainerfile() {
        #expect(template.containerfileContent == nil)
    }

    @Test func doesNotRequireSSH() {
        #expect(!template.requiresSSH)
    }
}

@Suite("SessionTracker")
struct SessionTrackerTests {
    @Test func createAndRemoveSession() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        let sessionId = try SessionTracker.create(for: containerId)
        #expect(SessionTracker.activeSessions(for: containerId) == 1)

        let wasLast = SessionTracker.remove(sessionId: sessionId, for: containerId)
        #expect(wasLast)
        #expect(SessionTracker.activeSessions(for: containerId) == 0)
    }

    @Test func multipleSessions() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        let s1 = try SessionTracker.create(for: containerId)
        let s2 = try SessionTracker.create(for: containerId)
        #expect(SessionTracker.activeSessions(for: containerId) == 2)

        let wasLast1 = SessionTracker.remove(sessionId: s1, for: containerId)
        #expect(!wasLast1)
        #expect(SessionTracker.activeSessions(for: containerId) == 1)

        let wasLast2 = SessionTracker.remove(sessionId: s2, for: containerId)
        #expect(wasLast2)
    }

    @Test func clearAllRemovesEverything() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        _ = try SessionTracker.create(for: containerId)
        _ = try SessionTracker.create(for: containerId)
        #expect(SessionTracker.activeSessions(for: containerId) == 2)

        SessionTracker.clearAll(for: containerId)
        #expect(SessionTracker.activeSessions(for: containerId) == 0)
    }

    @Test func noSessionsReturnsZero() {
        #expect(SessionTracker.activeSessions(for: "nonexistent-container") == 0)
    }
}

@Suite("SandboxManager")
struct SandboxManagerUtilTests {
    @Test func parseWorkspacePathPlain() {
        let (path, readOnly) = SandboxManager.parseWorkspacePath("/some/path")
        #expect(path == "/some/path")
        #expect(!readOnly)
    }

    @Test func parseWorkspacePathReadOnly() {
        let (path, readOnly) = SandboxManager.parseWorkspacePath("/some/path:ro")
        #expect(path == "/some/path")
        #expect(readOnly)
    }
}
