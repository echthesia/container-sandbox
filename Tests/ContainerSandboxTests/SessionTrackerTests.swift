import Foundation
@testable import sandbox
import Testing

/// Tests for SessionTracker using fake storage and controllable PID liveness.
struct FakeSessionTrackerTests {
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
        try storage.createSession(containerId: "c1", sessionId: "s3", pid: 1) // dead

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

    @Test func pidZeroWithDefaultPidIsAliveNeverCleaned() throws {
        // This documents the actual bug: default pidIsAlive uses kill($0, 0)
        // and kill(0, 0) succeeds, so PID 0 appears alive
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(
            storage: storage,
            pidIsAlive: { kill($0, 0) == 0 } // default behavior
        )

        try storage.createSession(containerId: "c1", sessionId: "zombie", pid: 0)
        let wasLast = tracker.remove(sessionId: "other", for: "c1")
        // BUG: PID 0 passes kill(0, 0) check, appears alive, never cleaned
        // Correct behavior would be wasLast == true
        #expect(wasLast, "PID 0 should not prevent container stop")
    }

    @Test func negativePIDWithDefaultPidIsAlive() throws {
        // kill(-1, 0) sends to all processes the user can signal — succeeds
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(
            storage: storage,
            pidIsAlive: { kill($0, 0) == 0 }
        )

        try storage.createSession(containerId: "c1", sessionId: "zombie", pid: -1)
        let wasLast = tracker.remove(sessionId: "other", for: "c1")
        // BUG: negative PID passes kill check, appears alive
        #expect(wasLast, "Negative PID should not prevent container stop")
    }

    // MARK: - Adversarial: error handling

    @Test func listSessionsErrorReturnsTrueStoppingContainer() throws {
        // If storage.listSessions throws, remove() returns true (last session),
        // which triggers container stop — even if sessions are still active
        let storage = FakeSessionStorage()
        let tracker = SessionTracker(storage: storage, pidIsAlive: { _ in true })

        try storage.createSession(containerId: "c1", sessionId: "s1", pid: 42)
        try storage.createSession(containerId: "c1", sessionId: "s2", pid: 43)

        // Now make listing fail
        storage.shouldThrowOnList = true

        let wasLast = tracker.remove(sessionId: "s1", for: "c1")
        // BUG: returns true because `try? storage.listSessions()` returns nil → true
        // Correct behavior: should return false (sessions still exist, we just can't read them)
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
