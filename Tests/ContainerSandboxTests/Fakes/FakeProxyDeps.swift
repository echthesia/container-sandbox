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
    var removedNames: [String] = []
    /// Tracks policies written via writePolicy, keyed by sandbox name.
    var writtenPolicies: [String: NetworkPolicy] = [:]
    /// When true, startIfNeeded's polling loop will find the socket.
    var socketAppearsAfterLaunch = true
    private var pendingSockets: Set<String> = []

    func ensureStateDirectory() throws {}

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

    func removeAll(for name: String) {
        states.removeValue(forKey: name)
        removedNames.append(name)
    }

    func writePolicy(_ policy: NetworkPolicy, for name: String) throws -> String {
        writtenPolicies[name] = policy
        return "/fake/config/\(name).json"
    }

    func socketExists(path: String) -> Bool {
        sockets.contains(path)
    }

    func removeSocket(path: String) {
        sockets.remove(path)
    }

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
