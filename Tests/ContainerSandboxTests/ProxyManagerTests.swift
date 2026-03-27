import Foundation
@testable import sandbox
import Testing

struct ProxyManagerTests {
    // MARK: - startIfNeeded

    @Test func alreadyRunningReturnsCachedSocket() async throws {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        // Pre-populate state: proxy already running with matching policy
        let existingState = ProxyState(pid: 42, socketPath: "/tmp/cs-proxy-existing.sock", sandboxName: "test")
        storage.states["test"] = existingState
        storage.sockets.insert("/tmp/cs-proxy-existing.sock")
        storage.writtenPolicies["test"] = .allow
        launcher.alivePIDs.insert(42)

        let socket = try await manager.startIfNeeded(name: "test", policy: .allow)
        #expect(socket == "/tmp/cs-proxy-existing.sock")
        #expect(launcher.launchCount == 0, "Should not launch a new process")
    }

    @Test func staleStateDeadPIDRestartsProxy() async throws {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        // Pre-populate state: proxy died (PID not alive)
        let staleState = ProxyState(pid: 42, socketPath: "/tmp/cs-proxy-old.sock", sandboxName: "test")
        storage.states["test"] = staleState
        storage.sockets.insert("/tmp/cs-proxy-old.sock")
        // PID 42 is NOT in launcher.alivePIDs → considered dead

        let socket = try await manager.startIfNeeded(name: "test", policy: .allow)
        #expect(launcher.launchCount == 1, "Should launch a new proxy")
        #expect(socket == ProxyManager.socketPath(for: "test"))
        // Old socket should have been cleaned up
        #expect(!storage.sockets.contains("/tmp/cs-proxy-old.sock"))
    }

    @Test func staleStateMissingSocketRestartsProxy() async throws {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        // Pre-populate state: PID alive but socket gone
        let staleState = ProxyState(pid: 42, socketPath: "/tmp/cs-proxy-gone.sock", sandboxName: "test")
        storage.states["test"] = staleState
        launcher.alivePIDs.insert(42)
        // Socket is NOT in storage.sockets → considered stale

        let socket = try await manager.startIfNeeded(name: "test", policy: .allow)
        #expect(launcher.launchCount == 1, "Should launch a new proxy")
        #expect(socket == ProxyManager.socketPath(for: "test"))
    }

    @Test func socketNeverAppearsThrowsError() async throws {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        storage.socketAppearsAfterLaunch = false // Socket never appears
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        await #expect(throws: SandboxError.self) {
            try await manager.startIfNeeded(name: "test", policy: .allow)
        }
    }

    // MARK: - stop

    @Test func stopKillsProcessAndCleansUp() {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        let state = ProxyState(pid: 42, socketPath: "/tmp/cs-proxy-test.sock", sandboxName: "test")
        storage.states["test"] = state
        storage.sockets.insert("/tmp/cs-proxy-test.sock")
        storage.writtenPolicies["test"] = .allow
        launcher.alivePIDs.insert(42)

        manager.stop(name: "test")

        #expect(launcher.killedPIDs.contains(42))
        #expect(!storage.sockets.contains("/tmp/cs-proxy-test.sock"))
        #expect(storage.removedNames.contains("test"))
        // Policy config must survive stop (persists across restart).
        #expect(storage.writtenPolicies["test"] == .allow,
                "stop() must preserve policy config for restart")
    }

    @Test func stopWithNoStateIsNoOp() {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        // No crash when stopping a proxy that doesn't exist
        manager.stop(name: "nonexistent")
        #expect(launcher.killedPIDs.isEmpty)
    }

    // MARK: - Socket path

    @Test func socketPathDeterministic() {
        let path1 = ProxyManager.socketPath(for: "my-sandbox")
        let path2 = ProxyManager.socketPath(for: "my-sandbox")
        #expect(path1 == path2)
    }

    @Test func socketPathDifferentForDifferentNames() {
        let path1 = ProxyManager.socketPath(for: "sandbox-a")
        let path2 = ProxyManager.socketPath(for: "sandbox-b")
        #expect(path1 != path2)
    }

    // MARK: - State round-trip

    @Test func proxyStateRoundTrip() throws {
        let original = ProxyState(pid: 42, socketPath: "/tmp/test.sock", sandboxName: "my-sandbox")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ProxyState.self, from: data)
        #expect(decoded.pid == original.pid)
        #expect(decoded.socketPath == original.socketPath)
        #expect(decoded.sandboxName == original.sandboxName)
    }

    @Test func corruptJSONFailsGracefully() {
        let data = Data("not json".utf8)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(ProxyState.self, from: data)
        }
    }

    // MARK: - Adversarial: socket path length

    @Test func socketPathWithinUDSLimit() {
        // macOS UDS limit is 104 bytes. Even with a very long sandbox name,
        // socketPath hashes it to 8 hex chars: "/tmp/cs-proxy-XXXXXXXX.sock"
        let longName = "sandbox-claude-" + String(repeating: "a", count: 500) + "-abcd1234"
        let path = ProxyManager.socketPath(for: longName)
        #expect(path.utf8.count <= 104, "Socket path \(path) exceeds 104-byte UDS limit")
        // Verify the format is consistent
        #expect(path.hasPrefix("/tmp/cs-proxy-"))
        #expect(path.hasSuffix(".sock"))
    }

    // MARK: - Adversarial: stale state — both PID dead AND socket missing

    @Test func staleStateBothDeadPIDAndMissingSocket() async throws {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        // PID dead AND socket missing — double failure
        let staleState = ProxyState(pid: 42, socketPath: "/tmp/cs-proxy-old.sock", sandboxName: "test")
        storage.states["test"] = staleState
        // PID 42 is NOT alive, socket is NOT in storage.sockets

        let socket = try await manager.startIfNeeded(name: "test", policy: .allow)
        #expect(launcher.launchCount == 1, "Should launch a new proxy")
        #expect(socket == ProxyManager.socketPath(for: "test"))
    }

    // MARK: - Adversarial: policy not checked on reuse

    @Test func reusedProxyDoesNotUpdatePolicy() async throws {
        // startIfNeeded with a running proxy returns the cached socket
        // WITHOUT writing the new policy. If the caller requests a different
        // policy, the old (possibly more permissive) policy stays active.
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        // First call — starts proxy with allow policy
        let socket1 = try await manager.startIfNeeded(name: "test", policy: .allow)
        #expect(launcher.launchCount == 1)
        #expect(storage.writtenPolicies["test"] == .allow)

        // Second call — requests deny policy, but proxy is already running
        let socket2 = try await manager.startIfNeeded(name: "test", policy: .deny)
        #expect(socket2 == socket1, "Reuses the same socket")

        // BUG: The policy should have been updated to .deny, but it wasn't.
        // The proxy is still running with the .allow policy from the first call.
        // This means a restrictive policy request is silently ignored.
        #expect(
            storage.writtenPolicies["test"] == .deny,
            "Policy should be updated when reusing a proxy with a different policy"
        )
    }

    // MARK: - Adversarial: launch failure

    @Test func launchFailurePropagatesError() async {
        let launcher = FakeProxyLauncher()
        launcher.shouldThrowOnLaunch = true
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        await #expect(throws: SandboxError.self) {
            try await manager.startIfNeeded(name: "test", policy: .allow)
        }
    }
}
