import Foundation

/// Abstracts filesystem operations for session tracking, enabling in-memory fakes in tests.
protocol SessionStorage: Sendable {
    func createSession(containerId: String, sessionId: String, pid: Int32) throws
    func removeSession(containerId: String, sessionId: String) throws
    func listSessions(containerId: String) throws -> [(sessionId: String, pid: Int32)]
    func clearAll(containerId: String)
}

/// Default filesystem-backed session storage.
struct FileSessionStorage: SessionStorage {
    private let baseDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/state/container-sandbox/sessions")

    private func sessionsDir(for containerId: String) -> URL {
        baseDir.appendingPathComponent(containerId)
    }

    func createSession(containerId: String, sessionId: String, pid: Int32) throws {
        let dir = sessionsDir(for: containerId)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let sessionFile = dir.appendingPathComponent(sessionId)
        try "\(pid)".write(to: sessionFile, atomically: true, encoding: .utf8)
    }

    func removeSession(containerId: String, sessionId: String) throws {
        let path = sessionsDir(for: containerId).appendingPathComponent(sessionId)
        try FileManager.default.removeItem(at: path)
    }

    func listSessions(containerId: String) throws -> [(sessionId: String, pid: Int32)] {
        let dir = sessionsDir(for: containerId)
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
            return []
        }
        var result: [(sessionId: String, pid: Int32)] = []
        for file in files {
            let filePath = dir.appendingPathComponent(file)
            guard let contents = try? String(contentsOf: filePath, encoding: .utf8),
                  let pid = Int32(contents.trimmingCharacters(in: .whitespacesAndNewlines))
            else {
                // Corrupt file — remove it
                try? FileManager.default.removeItem(at: filePath)
                continue
            }
            result.append((sessionId: file, pid: pid))
        }
        return result
    }

    func clearAll(containerId: String) {
        try? FileManager.default.removeItem(at: sessionsDir(for: containerId))
    }
}

/// Tracks active sandbox sessions via host-side files.
/// Each run/exec creates a session file containing the PID; on exit it's removed.
/// When the last session for a container exits, the container can be stopped.
struct SessionTracker {
    let storage: any SessionStorage
    let pidIsAlive: @Sendable (Int32) -> Bool

    init(
        storage: any SessionStorage = FileSessionStorage(),
        pidIsAlive: @Sendable @escaping (Int32) -> Bool = { kill($0, 0) == 0 }
    ) {
        self.storage = storage
        self.pidIsAlive = pidIsAlive
    }

    /// Register a new session. Returns the session ID.
    func create(for containerId: String) throws -> String {
        let sessionId = UUID().uuidString
        let pid = ProcessInfo.processInfo.processIdentifier
        try storage.createSession(containerId: containerId, sessionId: sessionId, pid: pid)
        return sessionId
    }

    /// Remove a session and return whether it was the last one.
    /// Cleans stale sessions (dead PIDs) in a single directory scan.
    func remove(sessionId: String, for containerId: String) -> Bool {
        try? storage.removeSession(containerId: containerId, sessionId: sessionId)

        guard let sessions = try? storage.listSessions(containerId: containerId) else {
            return false
        }

        var liveCount = 0
        for (id, pid) in sessions {
            if pid > 0 && pidIsAlive(pid) {
                liveCount += 1
            } else {
                try? storage.removeSession(containerId: containerId, sessionId: id)
            }
        }

        return liveCount == 0
    }

    /// Clear all sessions for a container (used by `sandbox stop`).
    func clearAll(for containerId: String) {
        storage.clearAll(containerId: containerId)
    }
}
