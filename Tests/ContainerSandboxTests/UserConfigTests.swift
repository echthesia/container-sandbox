import Foundation
@testable import sandbox
import Testing

struct UserConfigTests {
    @Test func loadMissingFileReturnsEmptyConfig() {
        let config = UserConfig.load(from: "/nonexistent/path/config.json")
        #expect(config.environment(for: "claude").isEmpty)
    }

    @Test func sharedEnvApplies() throws {
        let json = """
        {"env": {"KEY": "shared"}}
        """
        let config = try JSONDecoder().decode(UserConfig.self, from: Data(json.utf8))
        #expect(config.environment(for: "claude") == ["KEY": "shared"])
        #expect(config.environment(for: "shell") == ["KEY": "shared"])
    }

    @Test func agentEnvOverridesShared() throws {
        let json = """
        {
            "env": {"SHARED": "yes", "OVERRIDE": "shared"},
            "agents": {
                "claude": {"env": {"OVERRIDE": "agent", "AGENT_ONLY": "yes"}}
            }
        }
        """
        let config = try JSONDecoder().decode(UserConfig.self, from: Data(json.utf8))
        let env = config.environment(for: "claude")
        #expect(env["SHARED"] == "yes")
        #expect(env["OVERRIDE"] == "agent")
        #expect(env["AGENT_ONLY"] == "yes")
    }

    @Test func unknownAgentGetsOnlySharedEnv() throws {
        let json = """
        {
            "env": {"SHARED": "yes"},
            "agents": {"claude": {"env": {"CLAUDE_ONLY": "yes"}}}
        }
        """
        let config = try JSONDecoder().decode(UserConfig.self, from: Data(json.utf8))
        let env = config.environment(for: "shell")
        #expect(env == ["SHARED": "yes"])
    }

    @Test func malformedFileReturnsEmptyConfig() throws {
        let tmpFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("sandbox-test-bad-config.json").path
        try "not json".write(toFile: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let config = UserConfig.load(from: tmpFile)
        #expect(config.environment(for: "claude").isEmpty)
    }
}
