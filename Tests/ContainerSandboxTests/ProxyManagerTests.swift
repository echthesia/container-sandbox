import Foundation
import Testing

@testable import sandbox

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
        storage.socketAppearsAfterLaunch = false  // Socket never appears
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        await #expect(throws: SandboxError.self) {
            try await manager.startIfNeeded(name: "test", policy: .allow)
        }

        // The failed proxy should be killed and its runtime state cleaned up.
        #expect(launcher.killedPIDs == [1000], "Should kill the launched proxy")
        #expect(storage.removedNames.contains("test"), "Should remove runtime state")
        #expect(storage.states["test"] == nil, "Saved state should be cleared")
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
        #expect(
            storage.writtenPolicies["test"] == .allow,
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

    // MARK: - Policy change restarts proxy

    @Test func policyChangeRestartsProxy() async throws {
        let launcher = FakeProxyLauncher()
        let storage = FakeProxyStateStorage()
        let manager = ProxyManager(launcher: launcher, stateStorage: storage)

        // First call — starts proxy with allow policy
        let socket1 = try await manager.startIfNeeded(name: "test", policy: .allow)
        #expect(launcher.launchCount == 1)
        #expect(storage.writtenPolicies["test"] == .allow)

        // Second call — requests deny policy; proxy should restart with new policy.
        let socket2 = try await manager.startIfNeeded(name: "test", policy: .deny)
        #expect(socket2 == socket1, "Reuses the same socket path")
        #expect(launcher.launchCount == 2, "Should relaunch proxy for policy change")
        #expect(
            storage.writtenPolicies["test"] == .deny,
            "Policy should be updated when restarting proxy with a different policy"
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

    // MARK: - File permissions and lock-file persistence
    //
    // These exercise the live FileProxyStateStorage against a temp dir
    // (rather than the FakeProxyStateStorage used elsewhere in this file)
    // because the bug they catch is in actual filesystem syscalls.

    @Test func ensureStateDirectoryCreates0o700() throws {
        let tmp = makeTempStateDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let storage = FileProxyStateStorage(stateDir: tmp)

        try storage.ensureStateDirectory(for: "test-sandbox")

        #expect(modeBits(of: tmp) == 0o700)
        #expect(modeBits(of: tmp.appendingPathComponent("test-sandbox")) == 0o700)
    }

    @Test func policyFileWrittenAt0o600() throws {
        let tmp = makeTempStateDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let storage = FileProxyStateStorage(stateDir: tmp)

        try storage.ensureStateDirectory(for: "test-sandbox")
        let configPath = try storage.writePolicy(.deny, for: "test-sandbox")

        #expect(modeBits(of: URL(fileURLWithPath: configPath)) == 0o600)
    }

    @Test func proxyStateFileWrittenAt0o600() throws {
        let tmp = makeTempStateDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let storage = FileProxyStateStorage(stateDir: tmp)

        try storage.ensureStateDirectory(for: "test-sandbox")
        try storage.saveState(
            ProxyState(pid: 999, socketPath: "/tmp/x.sock", sandboxName: "test-sandbox"),
            for: "test-sandbox")

        let stateFile = tmp.appendingPathComponent("test-sandbox/proxy.json")
        #expect(modeBits(of: stateFile) == 0o600)
    }

    @Test func lockFileWrittenAt0o600() throws {
        let tmp = makeTempStateDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let storage = FileProxyStateStorage(stateDir: tmp)

        try storage.ensureStateDirectory(for: "test-sandbox")
        let lock = try storage.acquireLock(for: "test-sandbox")
        defer { withExtendedLifetime(lock) {} }

        let lockFile = tmp.appendingPathComponent("test-sandbox/proxy.lock")
        #expect(modeBits(of: lockFile) == 0o600)
    }

    @Test func removeRuntimeStatePreservesLockFile() throws {
        // The lock file must survive runtime teardown so flock semantics stay
        // path-stable across stop+start cycles for the same sandbox.
        let tmp = makeTempStateDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let storage = FileProxyStateStorage(stateDir: tmp)

        try storage.ensureStateDirectory(for: "test-sandbox")
        try storage.saveState(
            ProxyState(pid: 999, socketPath: "/tmp/x.sock", sandboxName: "test-sandbox"),
            for: "test-sandbox")
        let lock = try storage.acquireLock(for: "test-sandbox")
        defer { withExtendedLifetime(lock) {} }
        let logFile = tmp.appendingPathComponent("test-sandbox/proxy.log")
        FileManager.default.createFile(atPath: logFile.path, contents: nil)

        let stateFile = tmp.appendingPathComponent("test-sandbox/proxy.json")
        let lockFile = tmp.appendingPathComponent("test-sandbox/proxy.lock")

        storage.removeRuntimeState(for: "test-sandbox")

        #expect(!FileManager.default.fileExists(atPath: stateFile.path))
        #expect(!FileManager.default.fileExists(atPath: logFile.path))
        #expect(FileManager.default.fileExists(atPath: lockFile.path))
    }
}

// MARK: - Test helpers (file-perm assertions)

private func makeTempStateDir() -> URL {
    let base = URL(
        fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp",
        isDirectory: true)
    return base.appendingPathComponent("state-perms-\(UUID().uuidString)", isDirectory: true)
}

private func modeBits(of url: URL) -> mode_t {
    var st = stat()
    guard stat(url.path, &st) == 0 else { return 0 }
    return st.st_mode & 0o777
}
