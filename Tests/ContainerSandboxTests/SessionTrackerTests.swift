import Foundation
import Testing

@testable import sandbox

/// Tests for SessionTracker using fake storage and controllable PID liveness.
struct SessionTrackerUnitTests {
    // MARK: - Stale PID cleanup

    @Test func deadPIDsRemovedDuringRemoval() throws {
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage, pidIsAlive: { _ in false })

        // Create two sessions with "dead" PIDs
        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 100)
        try storage.createSession(containerId: "c1", sessionId: "s2", pid: 200)

        // Remove a non-existent session — should still scan and clean up dead PIDs
        let wasLast = tracker.remove(sessionId: "nonexistent", for: "c1")
        #expect(wasLast, "All PIDs are dead, should be last")

        // Verify dead sessions were cleaned up
        let remaining = try storage.listSessions(containerId: "c1")
        #expect(remaining.isEmpty)
    }

    @Test func livePIDsCountedAsActive() throws {
        let storage = FakeSessionStorage()
        let alivePIDs: Set<Int32> = [42, 99]
        let tracker = SessionTracker(
            storage: storage,
            pidIsAlive: { alivePIDs.contains($0) }
        )

        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 42)
        try storage.createSession(containerId: "c1", sessionId: "s2", pid: 99)
        try storage.createSession(containerId: "c1", sessionId: "s3", pid: 1)  // dead

        // Remove s1, but s2 is still alive
        let wasLast = tracker.remove(sessionId: "s1", for: "c1")
        #expect(!wasLast, "PID 99 is still alive")
    }

    // MARK: - Last session detection

    @Test func lastSessionReturnsTrue() throws {
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(
            storage: storage,
            pidIsAlive: { _ in true }
        )

        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 1)
        try storage.createSession(containerId: "c1", sessionId: "s2", pid: 2)
        try storage.createSession(containerId: "c1", sessionId: "s3", pid: 3)

        // Remove s1 — not last
        let first = tracker.remove(sessionId: "s1", for: "c1")
        #expect(!first)

        // Remove s2 — not last
        let second = tracker.remove(sessionId: "s2", for: "c1")
        #expect(!second)

        // Remove s3 — last
        let third = tracker.remove(sessionId: "s3", for: "c1")
        #expect(third)
    }

    // MARK: - clearAll

    @Test func clearAllIsIdempotent() {
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage, pidIsAlive: { _ in true })

        // Clear twice — no crash
        tracker.clearAll(for: "nonexistent")
        tracker.clearAll(for: "nonexistent")
    }

    @Test func clearAllThenCreateIsClean() throws {
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage, pidIsAlive: { _ in false })

        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 1)
        try storage.createSession(containerId: "c1", sessionId: "s2", pid: 2)

        tracker.clearAll(for: "c1")

        // New session after clear should be the only one
        try storage.createSession(containerId: "c1", sessionId: "s3", pid: 3)
        let sessions = try storage.listSessions(containerId: "c1")
        #expect(sessions.count == 1)
        #expect(sessions[0].sessionId == "s3")
    }

    // MARK: - Empty container

    @Test func removeFromEmptyContainerReturnsTrue() {
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage, pidIsAlive: { _ in true })

        let wasLast = tracker.remove(sessionId: "nonexistent", for: "empty-container")
        #expect(wasLast, "No sessions means container should stop")
    }

    // MARK: - Adversarial: PID edge cases

    @Test func pidZeroAppearsAliveViaKillSyscall() throws {
        // kill(0, 0) signals the caller's process group — always succeeds.
        // A session with PID 0 would appear permanently alive, never cleaned up.
        let storage = FakeSessionStorage()
        // Simulate the real pidIsAlive behavior for PID 0
        let tracker = SessionTracker(
            storage: storage,
            pidIsAlive: { pid in
                // PID 0 should NOT be considered a valid live session
                pid > 0
            }
        )

        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 0)
        let wasLast = tracker.remove(sessionId: "other", for: "c1")
        // With correct PID validation, PID 0 should be treated as dead
        #expect(wasLast, "PID 0 should be treated as dead, so no live sessions remain")
    }

    @Test func pidZeroWithDefaultPidIsAliveIsDead() throws {
        // Default pidIsAlive guards pid > 0, so PID 0 is correctly treated as dead
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage)  // uses default closure

        try storage.createSession(containerId: "c1", sessionId: "zombie", pid: 0)
        let wasLast = tracker.remove(sessionId: "other", for: "c1")
        #expect(wasLast, "PID 0 should be treated as dead")
    }

    @Test func negativePIDWithDefaultPidIsAliveIsDead() throws {
        // Default pidIsAlive guards pid > 0, so negative PIDs are correctly treated as dead
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage)  // uses default closure

        try storage.createSession(containerId: "c1", sessionId: "zombie", pid: -1)
        let wasLast = tracker.remove(sessionId: "other", for: "c1")
        #expect(wasLast, "Negative PID should be treated as dead")
    }

    // MARK: - Adversarial: error handling

    @Test func listSessionsErrorDoesNotStopContainer() throws {
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage, pidIsAlive: { _ in true })

        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 42)
        try storage.createSession(containerId: "c1", sessionId: "s2", pid: 43)

        storage.shouldThrowOnList = true

        let wasLast = tracker.remove(sessionId: "s1", for: "c1")
        #expect(!wasLast, "Storage error should not cause container stop when sessions may exist")
    }

    @Test func removeSessionErrorStillProceedsToList() throws {
        // If removeSession throws, the tracker should still list and count remaining
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage, pidIsAlive: { _ in true })

        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 42)
        try storage.createSession(containerId: "c1", sessionId: "s2", pid: 43)

        storage.shouldThrowOnRemove = true

        let wasLast = tracker.remove(sessionId: "s1", for: "c1")
        // Even though remove failed, s2 is still alive
        #expect(!wasLast, "Remove error should not prevent counting remaining sessions")
    }
}

/// Integration-style tests against the real on-disk SessionTracker storage.
/// Each test uses a fresh container ID so runs don't collide.
struct SessionTrackerIntegrationTests {
    let tracker = SessionTracker()

    @Test func createAndRemoveSession() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        let sessionId = try tracker.create(for: containerId)
        let wasLast = tracker.remove(sessionId: sessionId, for: containerId)
        #expect(wasLast)
    }

    @Test func multipleSessions() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        let s1 = try tracker.create(for: containerId)
        let s2 = try tracker.create(for: containerId)

        let wasLast1 = tracker.remove(sessionId: s1, for: containerId)
        #expect(!wasLast1)

        let wasLast2 = tracker.remove(sessionId: s2, for: containerId)
        #expect(wasLast2)
    }

    @Test func clearAllRemovesEverything() throws {
        let containerId = "test-container-\(UUID().uuidString)"
        _ = try tracker.create(for: containerId)
        _ = try tracker.create(for: containerId)

        tracker.clearAll(for: containerId)

        // Creating and immediately removing should show it's the last
        let s = try tracker.create(for: containerId)
        let wasLast = tracker.remove(sessionId: s, for: containerId)
        #expect(wasLast)
    }

    // MARK: - File permissions

    @Test func sessionFileWrittenAt0o600() throws {
        // Session files contain PIDs (not secret) but live alongside policy
        // and proxy state — the whole tree should be 0o700 / 0o600 so a
        // multi-user host can't see which sandboxes a user has running.
        let tmp = URL(
            fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp",
            isDirectory: true
        ).appendingPathComponent("session-perms-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        let storage = FileSessionStorage(baseDir: tmp)

        try storage.createSession(containerId: "test", sessionId: "abc", pid: 1234)

        let sessionFile = tmp.appendingPathComponent("test/sessions/abc")
        #expect(modeBits(of: sessionFile) == 0o600)
        #expect(modeBits(of: sessionFile.deletingLastPathComponent()) == 0o700)
        #expect(
            modeBits(of: sessionFile.deletingLastPathComponent().deletingLastPathComponent())
                == 0o700)
    }
}
