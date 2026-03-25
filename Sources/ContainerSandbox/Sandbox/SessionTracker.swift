import Foundation

/// Tracks active sandbox sessions via host-side files.
/// Each run/exec creates a session file containing the PID; on exit it's removed.
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
        let pid = ProcessInfo.processInfo.processIdentifier
        try "\(pid)".write(to: sessionFile, atomically: true, encoding: .utf8)

        return sessionId
    }

    /// Remove a session and return whether it was the last one.
    /// Cleans stale sessions (dead PIDs) in a single directory scan.
    static func remove(sessionId: String, for containerId: String) -> Bool {
        let dir = sessionsDir(for: containerId)

        // Remove our own session file
        try? FileManager.default.removeItem(at: dir.appendingPathComponent(sessionId))

        // Single scan: remove stale files and count remaining live ones
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
            return true
        }

        var liveCount = 0
        for file in files {
            let filePath = dir.appendingPathComponent(file)
            guard let contents = try? String(contentsOf: filePath, encoding: .utf8),
                  let pid = Int32(contents.trimmingCharacters(in: .whitespacesAndNewlines)),
                  kill(pid, 0) == 0 else {
                try? FileManager.default.removeItem(at: filePath)
                continue
            }
            liveCount += 1
        }

        return liveCount == 0
    }

    /// Clear all sessions for a container (used by `sandbox stop`).
    static func clearAll(for containerId: String) {
        try? FileManager.default.removeItem(at: sessionsDir(for: containerId))
    }
}
