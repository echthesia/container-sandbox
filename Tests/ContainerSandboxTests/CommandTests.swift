import Foundation
@testable import sandbox
import Testing

// Tests for the extracted command functions, exercising multi-step sequences,
// dispatch logic, and post-error state invariants that unit tests on individual
// components miss.

// MARK: - Multi-step state sequences

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
        #expect(h.proxyLauncher.killedPIDs.contains(existingState.pid),
                "Old proxy process should be killed on policy change")

        // A new proxy should have been launched.
        #expect(h.proxyLauncher.launchCount == 1,
                "A new proxy should be launched after killing the old one")

        // The persisted policy should now be "deny".
        let saved = try h.proxyStorage.loadPolicy(for: "my-sandbox")
        #expect(saved?.direction == .deny,
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
        #expect(h.proxyLauncher.launchCount == 0,
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
        #expect(h.proxyLauncher.launchCount == 2,
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
        #expect(saved?.direction == .allow,
                "Should fall back to template's default direction (allow)")
        // Should include the default allowed hosts and the new one.
        #expect(saved?.allowedHosts.contains("*.anthropic.com") == true,
                "Should inherit default allowed hosts")
        #expect(saved?.allowedHosts.contains("extra.com") == true,
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
        #expect(saved?.direction == .allow,
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
        #expect(saved?.direction == .allow,
                "Should use persisted direction, not template default")
        #expect(saved?.allowedHosts == ["custom.com"],
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
        #expect(saved?.allowedHosts.contains("a.com") == true,
                "Host should appear in allow list")
        #expect(saved?.blockedHosts.contains("a.com") != true,
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
        #expect(saved?.blockedHosts.contains("a.com") == true,
                "Host should appear in block list")
        #expect(saved?.allowedHosts.contains("a.com") != true,
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
        #expect(saved?.blockedHosts.isEmpty == true,
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
        #expect(saved?.blockedHosts.contains("conflict.com") == true,
                "Block should win when both are specified in the same call")
        #expect(saved?.allowedHosts.contains("conflict.com") != true,
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
        #expect(saved?.allowedHosts.contains("a.com") == true,
                "First allowed host should persist across calls")
        #expect(saved?.allowedHosts.contains("b.com") == true,
                "Second allowed host should be appended")
    }
}

struct ExtraWorkspaceRoundTripTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func duplicateExtrasProduceSameLabelAsDeduplicated() {
        // The label builder should produce identical output regardless of
        // whether duplicates are present, since mount creation deduplicates.
        let withDupes = SandboxManager.extraWorkspacesLabel([testWorkspace, testWorkspace])
        let withoutDupes = SandboxManager.extraWorkspacesLabel([testWorkspace])

        #expect(withDupes == withoutDupes,
                "Duplicate extras should be collapsed to match mount deduplication")
    }

    @Test func extraWorkspaceLabelIsPathNormalized() {
        // /path and /path/../path resolve to the same location.
        // The label should be identical for both.
        let direct = SandboxManager.extraWorkspacesLabel([testWorkspace])
        let indirect = SandboxManager.extraWorkspacesLabel([testWorkspace + "/../" + URL(fileURLWithPath: testWorkspace).lastPathComponent])

        #expect(direct == indirect,
                "Path-equivalent extras should produce the same label")
    }
}

// MARK: - CLI dispatch logic

struct CreateCommandDispatchTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func reservedNameIsRejected() async throws {
        let h = TestHarness()

        // "claude" is a registered agent template name — it should be
        // rejected as a sandbox name override.
        await #expect(throws: SandboxError.self) {
            try await createSandbox(
                agent: "claude", workspace: testWorkspace,
                nameOverride: "claude", manager: h.manager
            )
        }

        // No container should have been created.
        #expect(h.containers.createdConfigs.isEmpty,
                "No container should be created when the name is reserved")
    }

    @Test func reservedNameShellIsAlsoRejected() async throws {
        let h = TestHarness()

        await #expect(throws: SandboxError.self) {
            try await createSandbox(
                agent: "shell", workspace: testWorkspace,
                nameOverride: "shell", manager: h.manager
            )
        }
    }

    @Test func validNameOverrideCreatesWithThatName() async throws {
        let h = TestHarness()

        try await createSandbox(
            agent: "claude", workspace: testWorkspace,
            nameOverride: "my-custom-sandbox", manager: h.manager
        )

        #expect(h.containers.snapshots["my-custom-sandbox"] != nil,
                "Sandbox should be created with the overridden name")
    }

    @Test func unknownAgentThrowsUnknownAgent() async throws {
        let h = TestHarness()

        await #expect(throws: SandboxError.self) {
            try await createSandbox(
                agent: "nonexistent-agent", workspace: testWorkspace,
                manager: h.manager
            )
        }

        #expect(h.containers.createdConfigs.isEmpty)
    }
}

struct StopCommandTests {
    @Test func stopMultipleSandboxes() async throws {
        let h = TestHarness()

        h.containers.snapshots["sb-1"] = makeManagedSnapshot(
            name: "sb-1", agent: "claude", workspace: "/w1", status: .running
        )
        h.containers.snapshots["sb-2"] = makeManagedSnapshot(
            name: "sb-2", agent: "shell", workspace: "/w2", status: .running
        )

        try await stopSandboxes(names: ["sb-1", "sb-2"], manager: h.manager)

        #expect(h.containers.stoppedIds.contains("sb-1"))
        #expect(h.containers.stoppedIds.contains("sb-2"))
    }

    @Test func stopNonexistentSandboxReportsMissing() async throws {
        let h = TestHarness()

        // Stopping a nonexistent sandbox should not throw (stale host state
        // is cleaned up as a safety net), but should indicate it wasn't found.
        let found = try await h.manager.stopSandbox(name: "gone")
        #expect(!found, "Should report that no container was found to stop")
    }
}

struct RemoveCommandTests {
    @Test func removeDeletesContainerAndCleansAllState() async throws {
        let h = TestHarness()

        h.containers.snapshots["doomed"] = makeManagedSnapshot(
            name: "doomed", agent: "claude", workspace: "/w", status: .stopped
        )
        // Pre-populate proxy state to verify it gets cleaned up.
        try h.proxyStorage.writePolicy(.deny, for: "doomed")
        let state = ProxyState(pid: 999, socketPath: "/tmp/test.sock", sandboxName: "doomed")
        try h.proxyStorage.saveState(state, for: "doomed")

        try await removeSandboxes(names: ["doomed"], manager: h.manager)

        // Container should be gone.
        #expect(h.containers.deletedIds.contains("doomed"))
        // All proxy state — both policy and runtime — should be cleared.
        #expect(h.proxyStorage.writtenPolicies["doomed"] == nil,
                "Policy config should be removed")
        #expect(try h.proxyStorage.loadState(for: "doomed") == nil,
                "Runtime state should be removed")
    }

    @Test func removeNonexistentSandboxReportsMissing() async throws {
        let h = TestHarness()

        let found = try await h.manager.deleteSandbox(name: "gone")
        #expect(!found, "Should report that no container was found to remove")
    }

    @Test func removeRunningContainerStopsFirstThenDeletes() async throws {
        let h = TestHarness()

        h.containers.snapshots["running-sb"] = makeManagedSnapshot(
            name: "running-sb", agent: "claude", workspace: "/w", status: .running
        )

        try await removeSandboxes(names: ["running-sb"], manager: h.manager)

        // Should stop before deleting.
        #expect(h.containers.stoppedIds.contains("running-sb"),
                "Running container should be stopped before deletion")
        #expect(h.containers.deletedIds.contains("running-sb"),
                "Container should be deleted after stopping")
    }
}

// MARK: - Post-error state invariants

struct ErrorStateInvariantTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func configureProxyOnNonexistentSandboxHasNoSideEffects() async throws {
        let h = TestHarness()

        await #expect(throws: SandboxError.self) {
            try await configureNetworkProxy(
                sandboxName: "ghost", policy: .deny,
                manager: h.manager
            )
        }

        // No policy should have been written.
        #expect(h.proxyStorage.writtenPolicies.isEmpty,
                "Failed command should not leave partial proxy state")
        // No proxy should have been launched.
        #expect(h.proxyLauncher.launchCount == 0)
    }

    @Test func configureProxyOnUnmanagedContainerThrows() async throws {
        let h = TestHarness()

        // A container that exists but lacks the managed label.
        h.containers.snapshots["foreign"] = makeSnapshot(id: "foreign", status: .running)

        await #expect(throws: SandboxError.self) {
            try await configureNetworkProxy(
                sandboxName: "foreign", policy: .deny,
                manager: h.manager
            )
        }

        #expect(h.proxyStorage.writtenPolicies.isEmpty)
    }

    @Test func createWithMissingWorkspaceDoesNotCreateContainer() async throws {
        let h = TestHarness()

        await #expect(throws: SandboxError.self) {
            try await createSandbox(
                agent: "claude",
                workspace: "/nonexistent/path/that/does/not/exist",
                manager: h.manager
            )
        }

        #expect(h.containers.createdConfigs.isEmpty,
                "No container should be created when workspace doesn't exist")
        #expect(h.proxyLauncher.launchCount == 0,
                "No proxy should be launched when workspace doesn't exist")
    }
}
