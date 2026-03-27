import ContainerizationOCI
import ContainerResource
import Foundation
@testable import sandbox
import Testing

/// Uses a real temp directory as the workspace so fileExists checks pass.
private let testWorkspace = FileManager.default.temporaryDirectory.appendingPathComponent("sandbox-test-workspace").path

private struct TestHarness {
    let manager: SandboxManager
    let containers: FakeContainerOperations
    let images: FakeImageOperations
    let sessions: FakeSessionStorage
    let proxyStorage: FakeProxyStateStorage
}

struct SandboxManagerLifecycleTests {
    /// Shared setup: ensure test workspace exists.
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    private func makeManager(
        containers: FakeContainerOperations = FakeContainerOperations(),
        images: FakeImageOperations = FakeImageOperations(),
        sessions: FakeSessionStorage = FakeSessionStorage(),
        proxyStorage: FakeProxyStateStorage = FakeProxyStateStorage()
    ) -> TestHarness {
        // Images: agent image + init image both exist by default
        images.existingImages = ["container-sandbox-claude:latest", "docker.io/ubuntu:24.04", "container-sandbox-init:latest"]

        let sessionTracker = SessionTracker(storage: sessions, pidIsAlive: { _ in false })
        let proxyManager = ProxyManager(launcher: FakeProxyLauncher(), stateStorage: proxyStorage)
        let manager = SandboxManager(
            containers: containers,
            images: images,
            kernels: FakeKernelProvider(),
            sessions: sessionTracker,
            proxy: proxyManager
        )
        return TestHarness(manager: manager, containers: containers, images: images, sessions: sessions, proxyStorage: proxyStorage)
    }

    // MARK: - ensureSandboxExists: reuse existing

    @Test func existingSandboxWithMatchingLabelsIsReused() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)

        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "claude", workspace: resolvedWorkspace
        )

        let (resultName, _) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )
        #expect(resultName == name)
        #expect(h.containers.createdConfigs.isEmpty, "Should reuse, not create")
    }

    // MARK: - ensureSandboxExists: label mismatch detection

    @Test func mismatchedNetworkPolicyThrows() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)

        // Existing sandbox has allow policy
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "claude", workspace: resolvedWorkspace, policy: .allow
        )

        // Request deny policy
        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace,
                networkPolicy: .deny
            )
        }
    }

    @Test func mismatchedWorkspaceThrows() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)

        // Existing sandbox was created for a different workspace
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "claude", workspace: "/some/other/path",
            policy: ClaudeTemplate().defaultNetworkPolicy
        )

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace
            )
        }
    }

    @Test func mismatchedAgentThrows() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)

        // Existing sandbox has agent "shell" but we're requesting "claude"
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "shell", workspace: resolvedWorkspace,
            policy: ClaudeTemplate().defaultNetworkPolicy
        )

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace
            )
        }
    }

    @Test func outdatedSandboxMissingDirectionLabelThrows() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)

        // Sandbox exists but has no direction label (outdated format)
        h.containers.snapshots[name] = makeSnapshot(id: name, status: .stopped, labels: [
            SandboxLabels.managed: "true",
            SandboxLabels.agent: "claude",
            SandboxLabels.workspace: resolvedWorkspace,
            // No direction label!
        ])

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace
            )
        }
    }

    // MARK: - ensureSandboxExists: creation path

    @Test func nonexistentSandboxCreatesNew() async throws {
        let h = makeManager()

        let (name, _) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        #expect(!name.isEmpty)
        #expect(h.containers.createdConfigs.count == 1)

        let created = h.containers.createdConfigs[0]
        #expect(created.labels[SandboxLabels.managed] == "true")
        #expect(created.labels[SandboxLabels.agent] == "claude")
    }

    @Test func creationBuildsImageIfMissing() async throws {
        let h = makeManager()

        // Remove the agent image so it needs building
        h.images.existingImages.remove("container-sandbox-claude:latest")

        _ = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        #expect(h.images.builtImages.contains("container-sandbox-claude:latest"))
    }

    @Test func creationFailsIfInitImageMissing() async throws {
        let h = makeManager()

        // Remove init image
        h.images.existingImages.remove("container-sandbox-init:latest")

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace
            )
        }
    }

    @Test func workspaceNotFoundThrows() async throws {
        let h = makeManager()

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: "/nonexistent/path/that/does/not/exist"
            )
        }
    }

    // MARK: - bootstrapIfNeeded

    @Test func bootstrapRunningContainerIsNoop() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let snapshot = makeManagedSnapshot(
            name: "test-sandbox", agent: "claude", workspace: resolvedWorkspace,
            status: .running
        )
        h.containers.snapshots["test-sandbox"] = snapshot

        try await h.manager.bootstrapIfNeeded(name: "test-sandbox", snapshot: snapshot)
        #expect(h.containers.bootstrappedIds.isEmpty, "Should not bootstrap a running container")
    }

    @Test func bootstrapStoppedContainerBootstraps() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let snapshot = makeManagedSnapshot(
            name: "test-sandbox", agent: "claude", workspace: resolvedWorkspace,
            status: .stopped
        )
        h.containers.snapshots["test-sandbox"] = snapshot

        try await h.manager.bootstrapIfNeeded(name: "test-sandbox", snapshot: snapshot)
        #expect(h.containers.bootstrappedIds.contains("test-sandbox"))
    }

    @Test func bootstrapOutdatedSandboxThrows() async throws {
        let h = makeManager()

        // No direction label → outdated
        let snapshot = makeSnapshot(id: "test-sandbox", status: .stopped, labels: [
            SandboxLabels.managed: "true",
        ])
        h.containers.snapshots["test-sandbox"] = snapshot

        await #expect(throws: SandboxError.self) {
            try await h.manager.bootstrapIfNeeded(name: "test-sandbox", snapshot: snapshot)
        }
    }

    // MARK: - stopSandbox

    @Test func stopManagedSandboxStopsAndCleansUp() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        h.containers.snapshots["test-sandbox"] = makeManagedSnapshot(
            name: "test-sandbox", agent: "claude", workspace: resolvedWorkspace,
            status: .running
        )
        // Create a session to verify cleanup
        try h.sessions.createSession(containerId: "test-sandbox", sessionId: "s1", pid: 1)

        try await h.manager.stopSandbox(name: "test-sandbox")

        #expect(h.containers.stoppedIds.contains("test-sandbox"))
        // Sessions should be cleared
        let remaining = try h.sessions.listSessions(containerId: "test-sandbox")
        #expect(remaining.isEmpty)
    }

    @Test func stopNonManagedSandboxThrows() async throws {
        let h = makeManager()

        // Container exists but isn't managed by us
        h.containers.snapshots["foreign"] = makeSnapshot(id: "foreign", status: .running, labels: [:])

        await #expect(throws: SandboxError.self) {
            try await h.manager.stopSandbox(name: "foreign")
        }
    }

    @Test func stopAlreadyGoneContainerCleansUpHostResources() async throws {
        let h = makeManager()

        // No container exists, but we have leftover session state
        try h.sessions.createSession(containerId: "gone-sandbox", sessionId: "s1", pid: 1)

        // Should not throw — just cleans up host-side resources
        try await h.manager.stopSandbox(name: "gone-sandbox")

        let remaining = try h.sessions.listSessions(containerId: "gone-sandbox")
        #expect(remaining.isEmpty)
    }

    // MARK: - deleteSandbox

    @Test func deleteRunningContainerStopsThenDeletes() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        h.containers.snapshots["test-sandbox"] = makeManagedSnapshot(
            name: "test-sandbox", agent: "claude", workspace: resolvedWorkspace,
            status: .running
        )

        try await h.manager.deleteSandbox(name: "test-sandbox")

        #expect(h.containers.stoppedIds.contains("test-sandbox"))
        #expect(h.containers.deletedIds.contains("test-sandbox"))
    }

    @Test func deleteStoppedContainerDeletesDirectly() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        h.containers.snapshots["test-sandbox"] = makeManagedSnapshot(
            name: "test-sandbox", agent: "claude", workspace: resolvedWorkspace,
            status: .stopped
        )

        try await h.manager.deleteSandbox(name: "test-sandbox")

        #expect(h.containers.stoppedIds.isEmpty, "Should not stop an already-stopped container")
        #expect(h.containers.deletedIds.contains("test-sandbox"))
    }

    @Test func deleteNonManagedContainerThrows() async throws {
        let h = makeManager()

        h.containers.snapshots["foreign"] = makeSnapshot(id: "foreign", status: .stopped, labels: [:])

        await #expect(throws: SandboxError.self) {
            try await h.manager.deleteSandbox(name: "foreign")
        }
    }

    @Test func deleteGoneContainerCleansUpHostResources() async throws {
        let h = makeManager()

        try h.sessions.createSession(containerId: "gone", sessionId: "s1", pid: 1)

        // Should not throw
        try await h.manager.deleteSandbox(name: "gone")

        let remaining = try h.sessions.listSessions(containerId: "gone")
        #expect(remaining.isEmpty)
    }

    // MARK: - listSandboxes

    @Test func listFiltersToManagedOnly() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        h.containers.snapshots["managed"] = makeManagedSnapshot(
            name: "managed", agent: "claude", workspace: resolvedWorkspace
        )
        h.containers.snapshots["foreign"] = makeSnapshot(id: "foreign", status: .running, labels: [:])

        let list = try await h.manager.listSandboxes()
        #expect(list.count == 1)
        #expect(list[0].id == "managed")
    }

    // MARK: - Adversarial: container config inspection (mutation resistance)

    @Test func createdContainerUsesImageEnv() async throws {
        let h = makeManager()
        // Set non-nil image config with env vars — normally these come from the OCI image
        h.images.imageConfig = ImageConfig(env: ["PATH=/custom/bin", "LANG=C.UTF-8"])

        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        // The init process should inherit the image's environment
        #expect(config.initProcess.environment.contains("PATH=/custom/bin"),
                "Init process should use image env, not empty")
        #expect(config.initProcess.environment.contains("LANG=C.UTF-8"))
    }

    @Test func createdContainerUsesImageUser() async throws {
        let h = makeManager()
        h.images.imageConfig = ImageConfig(user: "sandbox")

        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        // The init process should use the image's USER, not default to root
        if case let .raw(userString) = config.initProcess.user {
            #expect(userString == "sandbox")
        } else if case let .id(uid, _) = config.initProcess.user {
            Issue.record("Expected .raw(\"sandbox\") user from image config, got .id(\(uid))")
        }
    }

    @Test func createdContainerDefaultsToRootWhenNoImageUser() async throws {
        let h = makeManager()
        // imageConfig is nil by default → should fall back to uid=0, gid=0
        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        if case let .id(uid, gid) = config.initProcess.user {
            #expect(uid == 0)
            #expect(gid == 0)
        } else {
            Issue.record("Expected .id(0, 0) default user, got \(config.initProcess.user)")
        }
    }

    @Test func createdContainerMountsProxySocketAtCorrectDestination() async throws {
        let h = makeManager()

        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        let proxyMount = config.mounts.first { $0.destination == "/run/proxy.sock" }
        #expect(proxyMount != nil,
                "Proxy socket must be mounted at /run/proxy.sock to match init-image bridge")
    }

    @Test func createdContainerHasCorrectResourceLimits() async throws {
        let h = makeManager()

        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        #expect(config.resources.cpus == ProcessInfo.processInfo.processorCount)
        #expect(config.resources.memoryInBytes == 8 * 1024 * 1024 * 1024,
                "Memory should be 8GB, not some other value")
    }

    @Test func createdContainerRespectsTemplateFlags() async throws {
        let h = makeManager()

        // ClaudeTemplate: ssh=true, virtualization=false, useInit=true
        _ = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        #expect(config.ssh == true, "ClaudeTemplate requires SSH")
        #expect(config.useInit == true, "ClaudeTemplate requires init")
    }

    @Test func createdContainerRespectsShellTemplateFlags() async throws {
        let h = makeManager()

        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        #expect(config.ssh == false, "ShellTemplate does not require SSH")
        #expect(config.useInit == true, "ShellTemplate uses init")
    }

    // MARK: - Adversarial: extra workspace duplicates primary

    @Test func extraWorkspaceDuplicatingPrimaryCreatesDuplicateMount() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)

        // Pass the same path as both primary and extra (with :ro)
        // This creates two virtiofs mounts at the same destination: one r/w, one r/o
        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace,
            extraWorkspaces: ["\(testWorkspace):ro"]
        )

        let config = h.containers.createdConfigs[0]
        let mountDests = config.mounts.map(\.destination)
        let duplicates = mountDests.filter { $0 == resolvedWorkspace }
        // BUG: Two mounts at the same destination with conflicting options
        // Correct behavior: should detect the duplicate and error or deduplicate
        #expect(duplicates.count <= 1, "Should not create conflicting mounts at the same destination")
    }

    // MARK: - Adversarial: CIDR notation breaks policy reuse

    @Test func cidrNotationDifferenceBreaksPolicyReuse() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: resolvedWorkspace)

        // Existing sandbox has "10.0.0.0/8" in CIDRs
        let existingPolicy = NetworkPolicy(
            direction: .allow,
            allowedHosts: NetworkPolicy.defaultAllowedHosts,
            blockedHosts: [],
            blockedCIDRs: ["10.0.0.0/8"]
        )
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "shell", workspace: resolvedWorkspace,
            policy: existingPolicy
        )

        // Request with "10.0.0.0/08" — semantically identical but different string
        let requestedPolicy = NetworkPolicy(
            direction: .allow,
            allowedHosts: NetworkPolicy.defaultAllowedHosts,
            blockedHosts: [],
            blockedCIDRs: ["10.0.0.0/08"]
        )

        // BUG: This throws networkPolicyMismatch because Set("10.0.0.0/8") != Set("10.0.0.0/08")
        // Correct behavior: should recognize these as the same CIDR and reuse
        let (resultName, _) = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace,
            networkPolicy: requestedPolicy
        )
        #expect(resultName == name, "Should reuse sandbox with semantically equivalent CIDR")
    }
}
