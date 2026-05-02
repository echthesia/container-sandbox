import Foundation

@testable import sandbox

/// Fake process launcher for testing ProxyManager without real processes.
final class FakeProxyLauncher: ProxyLauncher, @unchecked Sendable {
    var nextPID: Int32 = 1000
    var alivePIDs: Set<Int32> = []
    var killedPIDs: [Int32] = []
    var launchCount = 0
    var shouldThrowOnLaunch = false
    var launchedArguments: [[String]] = []

    func launch(executable _: String, arguments: [String], logPath _: URL) throws -> Int32 {
        if shouldThrowOnLaunch {
            throw SandboxError.proxyStartFailed("fake launch failure")
        }
        launchedArguments.append(arguments)
        launchCount += 1
        let pid = nextPID
        nextPID += 1
        alivePIDs.insert(pid)
        return pid
    }

    func isProcessAlive(pid: Int32) -> Bool {
        alivePIDs.contains(pid)
    }

    func killProcess(pid: Int32) {
        killedPIDs.append(pid)
        alivePIDs.remove(pid)
    }
}

/// Fake state storage for testing ProxyManager without filesystem.
final class FakeProxyStateStorage: ProxyStateStorage, @unchecked Sendable {
    var states: [String: ProxyState] = [:]
    var sockets: Set<String> = []
    /// Names passed to `removeRuntimeState`. Tracked separately from
    /// `removedAllNames` so tests can assert which API production invoked;
    /// aliasing them would silently mask a regression where production calls
    /// `removeRuntimeState` (preserves policy) instead of `removeAll`.
    var removedRuntimeNames: [String] = []
    /// Names passed to `removeAll`.
    var removedAllNames: [String] = []
    /// Tracks policies written via writePolicy, keyed by sandbox name.
    var writtenPolicies: [String: NetworkPolicy] = [:]
    /// When true, startIfNeeded's polling loop will find the socket.
    var socketAppearsAfterLaunch = true
    private var pendingSockets: Set<String> = []

    func ensureStateDirectory(for _: String) throws {}

    func loadState(for name: String) throws -> ProxyState? {
        states[name]
    }

    func saveState(_ state: ProxyState, for name: String) throws {
        states[name] = state
        // Simulate socket appearing after save (proxy started successfully)
        if socketAppearsAfterLaunch {
            sockets.insert(state.socketPath)
        }
    }

    func removeRuntimeState(for name: String) {
        states.removeValue(forKey: name)
        removedRuntimeNames.append(name)
    }

    func removeAll(for name: String) {
        states.removeValue(forKey: name)
        writtenPolicies.removeValue(forKey: name)
        removedAllNames.append(name)
    }

    @discardableResult
    func writePolicy(_ policy: NetworkPolicy, for name: String) throws -> String {
        writtenPolicies[name] = policy
        return "/fake/config/\(name).json"
    }

    func loadPolicy(for name: String) throws -> NetworkPolicy? {
        writtenPolicies[name]
    }

    func socketExists(path: String) -> Bool {
        sockets.contains(path)
    }

    func removeSocket(path: String) {
        sockets.remove(path)
    }

    func ensureSocketDir(for _: String) {}

    func removeSocketDir(for _: String) {}

    func logPath(for name: String) -> URL {
        URL(fileURLWithPath: "/fake/logs/\(name)-proxy.log")
    }

    func acquireLock(for _: String) throws -> ProxyLockHandle {
        // No-op lock for tests (returns a dummy fd that won't be used)
        // Use /dev/null as a harmless file descriptor
        let fd = open("/dev/null", O_RDONLY)
        return ProxyLockHandle(fd: fd)
    }
}
