import Foundation

/// Tracks active sandbox sessions via host-side files.
/// Each `run` creates a session file; on exit it's removed.
/// When the last session for a container exits, the container can be stopped.
enum SessionTracker {
    private static let baseDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/state/container-sandbox/sessions")

    private static func sessionsDir(for containerId: String) -> URL {
        baseDir.appendingPathComponent(containerId)
    }

    /// Register a new session. Returns the session ID.
    static func create(for containerId: String) throws -> String {
        let dir = sessionsDir(for: containerId)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let sessionId = UUID().uuidString
        let sessionFile = dir.appendingPathComponent(sessionId)

        // Write our PID so stale sessions can be detected
        let pid = ProcessInfo.processInfo.processIdentifier
        try "\(pid)".write(to: sessionFile, atomically: true, encoding: .utf8)

        return sessionId
    }

    /// Remove a session and return whether it was the last one.
    static func remove(sessionId: String, for containerId: String) -> Bool {
        let dir = sessionsDir(for: containerId)
        let sessionFile = dir.appendingPathComponent(sessionId)

        try? FileManager.default.removeItem(at: sessionFile)

        // Clean stale sessions (PIDs that no longer exist)
        cleanStaleSessions(for: containerId)

        // Check if any sessions remain
        return activeSessions(for: containerId) == 0
    }

    /// Count active (non-stale) sessions for a container.
    static func activeSessions(for containerId: String) -> Int {
        let dir = sessionsDir(for: containerId)
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
            return 0
        }
        return files.count
    }

    /// Remove session files whose PIDs are no longer running.
    static func cleanStaleSessions(for containerId: String) {
        let dir = sessionsDir(for: containerId)
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
            return
        }

        for file in files {
            let filePath = dir.appendingPathComponent(file)
            guard let contents = try? String(contentsOf: filePath, encoding: .utf8),
                  let pid = Int32(contents.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                // Can't read PID — remove as stale
                try? FileManager.default.removeItem(at: filePath)
                continue
            }

            // kill(pid, 0) checks if process exists without sending a signal
            if kill(pid, 0) != 0 {
                try? FileManager.default.removeItem(at: filePath)
            }
        }
    }

    /// Clear all sessions for a container (used by `sandbox stop`).
    static func clearAll(for containerId: String) {
        let dir = sessionsDir(for: containerId)
        try? FileManager.default.removeItem(at: dir)
    }
}
