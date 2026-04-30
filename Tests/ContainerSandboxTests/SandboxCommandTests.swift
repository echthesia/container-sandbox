import Foundation
import Testing

@testable import sandbox

// CLI dispatch tests for the create / stop / remove command paths, plus
// post-error state invariants. These exercise the command functions through
// TestHarness — unit-level lifecycle tests live in SandboxManagerTests.

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
        #expect(
            h.containers.createdConfigs.isEmpty,
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

        #expect(
            h.containers.snapshots["my-custom-sandbox"] != nil,
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
        #expect(
            h.proxyStorage.writtenPolicies["doomed"] == nil,
            "Policy config should be removed")
        #expect(
            try h.proxyStorage.loadState(for: "doomed") == nil,
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
        #expect(
            h.containers.stoppedIds.contains("running-sb"),
            "Running container should be stopped before deletion")
        #expect(
            h.containers.deletedIds.contains("running-sb"),
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
        #expect(
            h.proxyStorage.writtenPolicies.isEmpty,
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

        #expect(
            h.containers.createdConfigs.isEmpty,
            "No container should be created when workspace doesn't exist")
        #expect(
            h.proxyLauncher.launchCount == 0,
            "No proxy should be launched when workspace doesn't exist")
    }
}
