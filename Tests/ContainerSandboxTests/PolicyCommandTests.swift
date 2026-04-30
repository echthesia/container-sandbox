import Foundation
import Testing

@testable import sandbox

// Multi-step state-machine tests for the network-policy command surface
// (configureNetworkProxy + the allow/block-host helpers). Unit-level
// behavior of NetworkPolicy lives in PolicyResolutionTests; these tests
// drive sequences of commands through TestHarness to verify persistence,
// proxy lifecycle, fallback chains, and de-confliction.

struct PolicyChangeSequenceTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func policyChangeRestartsProxyOnRunningSandbox() async throws {
        let h = TestHarness()

        // Set up a running sandbox with an existing proxy and "allow" policy.
        h.containers.snapshots["my-sandbox"] = makeManagedSnapshot(
            name: "my-sandbox", agent: "claude", workspace: testWorkspace,
            status: .running
        )
        try h.proxyStorage.writePolicy(.allow, for: "my-sandbox")
        // Simulate a running proxy with a live PID.
        let existingState = ProxyState(
            pid: h.proxyLauncher.nextPID,
            socketPath: ProxyManager.socketPath(for: "my-sandbox"),
            sandboxName: "my-sandbox"
        )
        try h.proxyStorage.saveState(existingState, for: "my-sandbox")
        h.proxyLauncher.alivePIDs.insert(existingState.pid)
        // Advance nextPID past the one we manually used.
        h.proxyLauncher.nextPID += 1

        // Act: change policy from allow to deny.
        try await configureNetworkProxy(
            sandboxName: "my-sandbox", policy: .deny,
            manager: h.manager
        )

        // The old proxy should have been killed.
        #expect(
            h.proxyLauncher.killedPIDs.contains(existingState.pid),
            "Old proxy process should be killed on policy change")

        // A new proxy should have been launched.
        #expect(
            h.proxyLauncher.launchCount == 1,
            "A new proxy should be launched after killing the old one")

        // The persisted policy should now be "deny".
        let saved = try h.proxyStorage.loadPolicy(for: "my-sandbox")
        #expect(
            saved?.direction == .deny,
            "Persisted policy should reflect the update")
    }

    @Test func policyChangeOnStoppedSandboxPersistsWithoutLaunching() async throws {
        let h = TestHarness()

        h.containers.snapshots["my-sandbox"] = makeManagedSnapshot(
            name: "my-sandbox", agent: "claude", workspace: testWorkspace,
            status: .stopped
        )

        try await configureNetworkProxy(
            sandboxName: "my-sandbox", policy: .deny,
            allowHost: ["example.com"],
            manager: h.manager
        )

        // Policy should be persisted.
        let saved = try h.proxyStorage.loadPolicy(for: "my-sandbox")
        #expect(saved?.direction == .deny)
        #expect(saved?.allowedHosts.contains("example.com") == true)

        // No proxy should have been launched — sandbox isn't running.
        #expect(
            h.proxyLauncher.launchCount == 0,
            "Should not launch proxy for a stopped sandbox")
    }

    @Test func consecutivePolicyChangesEachRestartProxy() async throws {
        let h = TestHarness()

        h.containers.snapshots["my-sandbox"] = makeManagedSnapshot(
            name: "my-sandbox", agent: "claude", workspace: testWorkspace,
            status: .running
        )
        try h.proxyStorage.writePolicy(.allow, for: "my-sandbox")

        // First change: allow → deny.
        try await configureNetworkProxy(
            sandboxName: "my-sandbox", policy: .deny,
            manager: h.manager
        )
        #expect(h.proxyLauncher.launchCount == 1)

        // Second change: add a host to the deny policy.
        try await configureNetworkProxy(
            sandboxName: "my-sandbox", allowHost: ["extra.com"],
            manager: h.manager
        )

        // Second call should also trigger a restart since the policy changed again.
        #expect(
            h.proxyLauncher.launchCount == 2,
            "Each policy mutation on a running sandbox should restart the proxy")
    }
}

struct PolicyFallbackTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func noExistingPolicyFallsBackToTemplateDefault() async throws {
        let h = TestHarness()

        // A claude sandbox with no policy on disk. The fallback chain should
        // reach ClaudeTemplate.defaultNetworkPolicy (deny with *.claude.ai).
        h.containers.snapshots["my-sandbox"] = makeManagedSnapshot(
            name: "my-sandbox", agent: "claude", workspace: testWorkspace,
            status: .stopped
        )

        // Add a host — this triggers the mutation path which loads the base.
        try await configureNetworkProxy(
            sandboxName: "my-sandbox", allowHost: ["extra.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "my-sandbox")
        // Should inherit the template's allow direction.
        #expect(
            saved?.direction == .allow,
            "Should fall back to template's default direction (allow)")
        // Should include the default allowed hosts and the new one.
        #expect(
            saved?.allowedHosts.contains("*.anthropic.com") == true,
            "Should inherit default allowed hosts")
        #expect(
            saved?.allowedHosts.contains("extra.com") == true,
            "Should include the newly added host")
    }

    @Test func unknownAgentLabelFallsBackToAllow() async throws {
        let h = TestHarness()

        // A sandbox whose agent label doesn't resolve to any template.
        h.containers.snapshots["orphan"] = makeManagedSnapshot(
            name: "orphan", agent: "deleted-agent", workspace: testWorkspace,
            status: .stopped
        )

        try await configureNetworkProxy(
            sandboxName: "orphan", blockHost: ["evil.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "orphan")
        // With no template match, falls back to .allow.
        #expect(
            saved?.direction == .allow,
            "Should fall back to .allow when agent template is unknown")
        #expect(saved?.blockedHosts.contains("evil.com") == true)
    }

    @Test func existingPolicyTakesPrecedenceOverTemplateDefault() async throws {
        let h = TestHarness()

        h.containers.snapshots["my-sandbox"] = makeManagedSnapshot(
            name: "my-sandbox", agent: "claude", workspace: testWorkspace,
            status: .stopped
        )
        // Write a custom policy that differs from the template default.
        var custom = NetworkPolicy.allow
        custom.allowedHosts = ["custom.com"]
        try h.proxyStorage.writePolicy(custom, for: "my-sandbox")

        try await configureNetworkProxy(
            sandboxName: "my-sandbox", blockHost: ["bad.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "my-sandbox")
        // Should build on the persisted policy, not the template default.
        #expect(
            saved?.direction == .allow,
            "Should use persisted direction, not template default")
        #expect(
            saved?.allowedHosts == ["custom.com"],
            "Should preserve existing allowed hosts from persisted policy")
        #expect(saved?.blockedHosts.contains("bad.com") == true)
    }
}

struct PolicyDeconflictionTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func allowHostRemovesFromBlockList() async throws {
        let h = TestHarness()

        h.containers.snapshots["sb"] = makeManagedSnapshot(
            name: "sb", agent: "shell", workspace: testWorkspace,
            status: .stopped
        )
        // Start with a.com blocked.
        var base = NetworkPolicy.allow
        base.blockedHosts = ["a.com"]
        try h.proxyStorage.writePolicy(base, for: "sb")

        // Allow a.com — should remove it from the block list.
        try await configureNetworkProxy(
            sandboxName: "sb", allowHost: ["a.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "sb")
        #expect(
            saved?.allowedHosts.contains("a.com") == true,
            "Host should appear in allow list")
        #expect(
            saved?.blockedHosts.contains("a.com") != true,
            "Host should be removed from block list")
    }

    @Test func blockHostRemovesFromAllowList() async throws {
        let h = TestHarness()

        h.containers.snapshots["sb"] = makeManagedSnapshot(
            name: "sb", agent: "shell", workspace: testWorkspace,
            status: .stopped
        )
        var base = NetworkPolicy.allow
        base.allowedHosts = ["a.com"]
        try h.proxyStorage.writePolicy(base, for: "sb")

        // Block a.com — should remove it from the allow list.
        try await configureNetworkProxy(
            sandboxName: "sb", blockHost: ["a.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "sb")
        #expect(
            saved?.blockedHosts.contains("a.com") == true,
            "Host should appear in block list")
        #expect(
            saved?.allowedHosts.contains("a.com") != true,
            "Host should be removed from allow list")
    }

    @Test func deconflictionIsCaseInsensitive() async throws {
        let h = TestHarness()

        h.containers.snapshots["sb"] = makeManagedSnapshot(
            name: "sb", agent: "shell", workspace: testWorkspace,
            status: .stopped
        )
        var base = NetworkPolicy.allow
        base.blockedHosts = ["Evil.COM"]
        try h.proxyStorage.writePolicy(base, for: "sb")

        // Allow with different casing — should still remove from block.
        try await configureNetworkProxy(
            sandboxName: "sb", allowHost: ["evil.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "sb")
        #expect(saved?.allowedHosts.contains("evil.com") == true)
        #expect(
            saved?.blockedHosts.isEmpty == true,
            "Case-different blocked entry should be removed")
    }

    @Test func allowAndBlockInSameCallBlockWins() async throws {
        let h = TestHarness()

        h.containers.snapshots["sb"] = makeManagedSnapshot(
            name: "sb", agent: "shell", workspace: testWorkspace,
            status: .stopped
        )
        try h.proxyStorage.writePolicy(.allow, for: "sb")

        // Passing the same host to both --allow-host and --block-host in one call.
        // Block is applied second, so it should win.
        try await configureNetworkProxy(
            sandboxName: "sb", allowHost: ["conflict.com"],
            blockHost: ["conflict.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "sb")
        #expect(
            saved?.blockedHosts.contains("conflict.com") == true,
            "Block should win when both are specified in the same call")
        #expect(
            saved?.allowedHosts.contains("conflict.com") != true,
            "Allow entry should be removed by the subsequent block")
    }
}

struct PolicyAccumulationTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func consecutiveAllowHostsAccumulate() async throws {
        let h = TestHarness()

        h.containers.snapshots["sb"] = makeManagedSnapshot(
            name: "sb", agent: "shell", workspace: testWorkspace,
            status: .stopped
        )
        try h.proxyStorage.writePolicy(.allow, for: "sb")

        try await configureNetworkProxy(
            sandboxName: "sb", allowHost: ["a.com"],
            manager: h.manager
        )
        try await configureNetworkProxy(
            sandboxName: "sb", allowHost: ["b.com"],
            manager: h.manager
        )

        let saved = try h.proxyStorage.loadPolicy(for: "sb")
        #expect(
            saved?.allowedHosts.contains("a.com") == true,
            "First allowed host should persist across calls")
        #expect(
            saved?.allowedHosts.contains("b.com") == true,
            "Second allowed host should be appended")
    }
}
