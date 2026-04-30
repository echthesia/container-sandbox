import Foundation

@testable import sandbox

/// In-memory session storage for testing SessionTracker without filesystem.
final class FakeSessionStorage: SessionStorage, @unchecked Sendable {
    private var sessions: [String: [(sessionId: String, pid: Int32)]] = [:]

    /// When true, `listSessions` throws instead of returning data.
    var shouldThrowOnList = false
    /// When true, `removeSession` throws instead of removing.
    var shouldThrowOnRemove = false

    func createSession(containerId: String, sessionId: String, pid: Int32) throws {
        sessions[containerId, default: []].append((sessionId: sessionId, pid: pid))
    }

    func removeSession(containerId: String, sessionId: String) throws {
        if shouldThrowOnRemove {
            throw SandboxError.proxyStartFailed("fake remove failure")
        }
        sessions[containerId]?.removeAll { $0.sessionId == sessionId }
    }

    func listSessions(containerId: String) throws -> [(sessionId: String, pid: Int32)] {
        if shouldThrowOnList {
            throw SandboxError.proxyStartFailed("fake list failure")
        }
        return sessions[containerId] ?? []
    }

    func clearAll(containerId: String) {
        sessions.removeValue(forKey: containerId)
    }
}
