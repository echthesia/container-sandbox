import ContainerResource
import Foundation
@testable import sandbox
import Testing

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
        #expect(template.containerfileContent != nil)
        #expect(try #require(template.containerfileContent?.contains("ubuntu:24.04")))
        #expect(try #require(template.containerfileContent?.contains("claude.ai/install.sh")))
        #expect(try #require(template.containerfileContent?.contains("sandbox")))
    }

    @Test func passesThroughAPIKeys() {
        #expect(template.passthroughEnvironment.contains("ANTHROPIC_API_KEY"))
        #expect(template.passthroughEnvironment.contains("CLAUDE_CODE_OAUTH_TOKEN"))
    }
}

struct SessionTrackerTests {
    let tracker = SessionTracker()

    @Test func createAndRemoveSession() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        let sessionId = try tracker.create(for: containerId)
        let wasLast = tracker.remove(sessionId: sessionId, for: containerId)
        #expect(wasLast)
    }

    @Test func multipleSessions() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        let s1 = try tracker.create(for: containerId)
        let s2 = try tracker.create(for: containerId)

        let wasLast1 = tracker.remove(sessionId: s1, for: containerId)
        #expect(!wasLast1)

        let wasLast2 = tracker.remove(sessionId: s2, for: containerId)
        #expect(wasLast2)
    }

    @Test func clearAllRemovesEverything() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        _ = try tracker.create(for: containerId)
        _ = try tracker.create(for: containerId)

        tracker.clearAll(for: containerId)

        // Creating and immediately removing should show it's the last
        let s = try tracker.create(for: containerId)
        let wasLast = tracker.remove(sessionId: s, for: containerId)
        #expect(wasLast)
    }
}

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

// MARK: - ProcessConfiguration building

struct ProcessConfigurationTests {
    let baseConfig = ProcessConfiguration(
        executable: "/bin/sleep",
        arguments: ["infinity"],
        environment: ["PATH=/usr/bin", "HOME=/root"],
        workingDirectory: "/",
        user: .id(uid: 1000, gid: 1000)
    )

    @Test func inheritsUserFromBaseConfig() {
        let template = ShellTemplate()
        let config = template.processConfiguration(
            baseConfig: baseConfig,
            workingDirectory: "/workspace"
        )
        // User should be inherited from baseConfig, not overridden
        if case let .id(uid, gid) = config.user {
            #expect(uid == 1000)
            #expect(gid == 1000)
        } else {
            Issue.record("Expected .id user, got \(config.user)")
        }
    }

    @Test func extraArgsAppendedAfterEntrypoint() {
        let template = ClaudeTemplate()
        let config = template.processConfiguration(
            baseConfig: baseConfig,
            workingDirectory: "/workspace",
            extraArgs: ["--verbose", "--model", "opus"]
        )
        // Claude entrypoint: ["/home/sandbox/.local/bin/claude", "--dangerously-skip-permissions"]
        #expect(config.executable == "/home/sandbox/.local/bin/claude")
        #expect(config.arguments.contains("--dangerously-skip-permissions"))
        #expect(config.arguments.contains("--verbose"))
        #expect(config.arguments.contains("--model"))
        #expect(config.arguments.contains("opus"))
    }

    @Test func envLayerOrdering() {
        let template = ShellTemplate()
        let config = template.processConfiguration(
            baseConfig: baseConfig,
            workingDirectory: "/workspace",
            extraEnv: ["CUSTOM": "val"]
        )
        // Should contain base env, template defaults, and extras
        let keys = Set(config.environment.compactMap { parseEnvEntry($0)?.key })
        #expect(keys.contains("PATH")) // from base
        #expect(keys.contains("TERM")) // from template defaults
        #expect(keys.contains("CUSTOM")) // from extras
        #expect(keys.contains("HTTPS_PROXY")) // from proxy
    }

    @Test func templateDefaultsOverrideBase() {
        // ShellTemplate sets TERM=xterm-256color. If base also has TERM, template wins.
        let baseWithTerm = ProcessConfiguration(
            executable: "/bin/sleep",
            arguments: ["infinity"],
            environment: ["TERM=vt100"],
            workingDirectory: "/"
        )
        let template = ShellTemplate()
        let config = template.processConfiguration(
            baseConfig: baseWithTerm,
            workingDirectory: "/workspace"
        )
        // Template default TERM comes after base TERM → template wins
        #expect(config.environment.contains("TERM=xterm-256color"))
        #expect(!config.environment.contains("TERM=vt100"))
    }

    @Test func callerExtrasOverrideTemplateDefaults() {
        let template = ShellTemplate()
        let config = template.processConfiguration(
            baseConfig: baseConfig,
            workingDirectory: "/workspace",
            extraEnv: ["TERM": "dumb"]
        )
        // Extras come after template defaults → extras win
        #expect(config.environment.contains("TERM=dumb"))
        #expect(!config.environment.contains("TERM=xterm-256color"))
    }

    @Test func proxyVarsAlwaysWin() {
        let template = ShellTemplate()
        let config = template.processConfiguration(
            baseConfig: baseConfig,
            workingDirectory: "/workspace",
            extraEnv: ["HTTPS_PROXY": "http://custom:9999"]
        )
        // Proxy vars are added last → always win
        let httpsProxy = config.environment.first { $0.hasPrefix("HTTPS_PROXY=") }
        #expect(httpsProxy == "HTTPS_PROXY=http://127.0.0.1:\(ProxyManager.proxyPort)")
    }

    @Test func noDuplicateKeysInOutput() {
        let template = ClaudeTemplate()
        let config = template.processConfiguration(
            baseConfig: ProcessConfiguration(
                executable: "/bin/sleep",
                arguments: ["infinity"],
                environment: ["TERM=vt100", "PATH=/usr/bin", "LANG=C"],
                workingDirectory: "/"
            ),
            workingDirectory: "/workspace",
            extraEnv: ["TERM": "screen", "EXTRA": "1"]
        )
        let keys = config.environment.compactMap { parseEnvEntry($0)?.key }
        #expect(keys.count == Set(keys).count, "Duplicate keys found in environment")
    }
}
