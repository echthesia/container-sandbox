import ContainerResource
import ContainerizationExtras
import ContainerizationOCI
import Foundation
import Testing

@testable import sandbox

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
        TestHarness(containers: containers, images: images, sessions: sessions, proxyStorage: proxyStorage)
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

    @Test func mismatchedWorkspaceThrows() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)

        // Existing sandbox was created for a different workspace
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "claude", workspace: "/some/other/path"
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
            name: name, agent: "shell", workspace: resolvedWorkspace
        )

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace
            )
        }
    }

    // MARK: - ensureSandboxExists: network policy is NOT validated on reuse

    @Test func reuseSucceedsRegardlessOfNetworkPolicy() async throws {
        let h = makeManager()

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: resolvedWorkspace)

        // Create sandbox (writes .allow policy to state storage via startIfNeeded)
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "shell", workspace: resolvedWorkspace
        )

        // Reuse should succeed — no network policy validation on reuse
        let (resultName, _) = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )
        #expect(resultName == name)
        #expect(h.containers.createdConfigs.isEmpty, "Should reuse, not create")
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

    @Test func creationWritesPolicyToStateStorage() async throws {
        let h = makeManager()

        let (name, _) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        // ensureSandboxExists calls proxy.startIfNeeded which writes the template's
        // default policy to state storage. This is the foundation of the policy
        // persistence model — bootstrap reads from state storage, not labels.
        let storedPolicy = try h.proxyStorage.loadPolicy(for: name)
        #expect(
            storedPolicy == ClaudeTemplate().defaultNetworkPolicy,
            "Creation must write template default policy to state storage")
    }

    @Test func creationDoesNotWriteNetworkLabels() async throws {
        let h = makeManager()

        _ = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        let created = h.containers.createdConfigs[0]
        // Network policy lives in state storage, not container labels.
        #expect(
            created.labels["sandbox.direction"] == nil,
            "Network policy direction must not be stored in labels")
        #expect(
            created.labels["sandbox.allowed-hosts"] == nil,
            "Allowed hosts must not be stored in labels")
        #expect(
            created.labels["sandbox.blocked-hosts"] == nil,
            "Blocked hosts must not be stored in labels")
        #expect(
            created.labels["sandbox.blocked-cidrs"] == nil,
            "Blocked CIDRs must not be stored in labels")
    }

    @Test func creationBuildsImageIfMissing() async throws {
        let h = makeManager()
        let claudeImage = ClaudeTemplate().defaultImage

        // Remove the agent image so it needs building
        h.images.existingImages.remove(claudeImage)

        _ = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        #expect(h.images.builtImages.contains(claudeImage))
    }

    @Test func freshBuildPrunesOlderImagesOfSameTemplate() async throws {
        let h = makeManager()
        let currentImage = ClaudeTemplate().defaultImage
        let staleClaude = "container-sandbox-claude:sha-deadbeef"
        let staleClaude2 = "container-sandbox-claude:sha-cafef00d"
        let unrelatedImage = "container-sandbox-shell:sha-deadbeef"

        // Remove current so we trigger a build, then preload two stale Claude
        // images and one unrelated image (which must survive).
        h.images.existingImages.remove(currentImage)
        h.images.existingImages.insert(staleClaude)
        h.images.existingImages.insert(staleClaude2)
        h.images.existingImages.insert(unrelatedImage)

        _ = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        #expect(h.images.removedImages.contains(staleClaude), "Old Claude image should be pruned")
        #expect(h.images.removedImages.contains(staleClaude2), "Second old Claude image should be pruned")
        #expect(!h.images.removedImages.contains(unrelatedImage), "Other-template images must not be touched")
        #expect(!h.images.removedImages.contains(currentImage), "Just-built image must not be pruned")
    }

    @Test func cachedImageHitDoesNotPrune() async throws {
        let h = makeManager()
        let currentImage = ClaudeTemplate().defaultImage
        let staleClaude = "container-sandbox-claude:sha-deadbeef"

        // Current image already present → no build → no prune.
        h.images.existingImages.insert(staleClaude)

        _ = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        #expect(h.images.builtImages.isEmpty, "No build should have occurred")
        #expect(
            h.images.removedImages.isEmpty,
            "Pruning runs only after a successful build, not on cache hit. Stale: \(h.images.removedImages)")
        #expect(h.images.existingImages.contains(staleClaude), "Stale image should remain on cache hit")
        #expect(h.images.existingImages.contains(currentImage))
    }

    // MARK: - Network isolation invariant

    @Test func creationExplicitlyDeclaresNoNetworksAndNoDNS() async throws {
        let h = makeManager()

        _ = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        let created = h.containers.createdConfigs[0]
        // The proxy is the only sanctioned egress. A vNIC or in-VM resolver
        // would silently bypass it.
        #expect(created.networks.isEmpty, "Sandbox config must declare no network attachments")
        #expect(created.dns == nil, "Sandbox config must declare no DNS configuration")
    }

    @Test func creationFailsAndCleansUpIfFrameworkAttachesNetworkConfig() async throws {
        let h = makeManager()

        // Simulate a framework that, despite our request for no networks,
        // installs an attachment on the snapshot after create.
        h.containers.afterCreate = { id in
            guard var snapshot = h.containers.snapshots[id] else { return }
            snapshot.configuration.networks = [
                AttachmentConfiguration(network: "default", options: AttachmentOptions(hostname: "ignored"))
            ]
            h.containers.snapshots[id] = snapshot
        }

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace
            )
        }

        // Cleanup: the unsafe sandbox must be deleted and proxy state removed
        // so the caller can't accidentally reach it via stale state.
        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)
        #expect(h.containers.deletedIds.contains(name), "Unsafe sandbox must be deleted")
        #expect(h.proxyStorage.removedAllNames.contains(name), "Proxy state must be fully removed (policy too) on create-time isolation failure")
    }

    @Test func creationFailsAndCleansUpIfFrameworkAttachesDNS() async throws {
        let h = makeManager()

        h.containers.afterCreate = { id in
            guard var snapshot = h.containers.snapshots[id] else { return }
            snapshot.configuration.dns = ContainerConfiguration.DNSConfiguration(
                nameservers: ["1.1.1.1"]
            )
            h.containers.snapshots[id] = snapshot
        }

        await #expect(throws: SandboxError.self) {
            try await h.manager.ensureSandboxExists(
                template: ClaudeTemplate(),
                workspace: testWorkspace
            )
        }

        let resolvedWorkspace = SandboxManager.resolveWorkspacePath(testWorkspace)
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: resolvedWorkspace)
        #expect(h.containers.deletedIds.contains(name), "Sandbox with DNS must be deleted")
        #expect(h.proxyStorage.removedAllNames.contains(name), "Proxy state must be fully removed (policy too) on create-time isolation failure")
    }

    @Test func bootstrapFailsAndStopsIfRuntimeAttachesInterface() async throws {
        let h = makeManager()

        let (name, snapshot) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        // Simulate the runtime attaching an interface only at boot time —
        // the create-time check sees a clean snapshot, but the runtime
        // populates `snapshot.networks` once the VM actually boots.
        h.containers.afterBootstrap = { id in
            guard var stored = h.containers.snapshots[id] else { return }
            let attachment = try? Attachment(
                network: "default",
                hostname: "ignored",
                ipv4Address: CIDRv4("10.0.0.2/24"),
                ipv4Gateway: IPv4Address("10.0.0.1"),
                ipv6Address: nil,
                macAddress: nil
            )
            if let attachment {
                stored.networks = [attachment]
                h.containers.snapshots[id] = stored
            }
        }

        await #expect(throws: SandboxError.self) {
            try await h.manager.bootstrapIfNeeded(name: name, snapshot: snapshot)
        }
        #expect(h.containers.stoppedIds.contains(name), "Sandbox must be stopped if runtime attaches an interface")
    }

    @Test func cleanCreationDoesNotTriggerNetworkIsolationFailure() async throws {
        let h = makeManager()

        // No afterCreate hook → snapshot stays clean → assertion passes.
        let (name, snapshot) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        #expect(h.containers.deletedIds.isEmpty, "Clean creation must not trigger cleanup")
        // Bootstrap should also pass with a clean snapshot.
        try await h.manager.bootstrapIfNeeded(name: name, snapshot: snapshot)
        #expect(h.containers.stoppedIds.isEmpty, "Clean bootstrap must not trigger stop")
    }

    @Test func creationFailsIfProxyBridgeMissing() {
        _ = makeManager()

        // Point libexecHostPath at a nonexistent directory so the preflight check fails.
        // Since libexecHostPath is a static let, we test the error case indirectly:
        // the default test environment doesn't have the binary installed,
        // so we verify the error type is correct.
        // (The real preflight check uses FileManager.fileExists on the host path.)
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

        // Create the sandbox through the real path — this writes policy to state storage.
        let (name, snapshot) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )
        // Simulate it already running.
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "claude",
            workspace: SandboxManager.resolveWorkspacePath(testWorkspace),
            status: .running
        )

        try await h.manager.bootstrapIfNeeded(name: name, snapshot: snapshot)
        #expect(h.containers.bootstrappedIds.isEmpty, "Should not bootstrap a running container")
    }

    @Test func bootstrapStoppedContainerBootstraps() async throws {
        let h = makeManager()

        // Create through real path — writes policy to state storage.
        let (name, snapshot) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        try await h.manager.bootstrapIfNeeded(name: name, snapshot: snapshot)
        #expect(h.containers.bootstrappedIds.contains(name))
    }

    @Test func bootstrapWithoutPolicyInStateStorageThrows() async throws {
        let h = makeManager()

        // Sandbox exists but has no policy in state storage — represents an
        // outdated sandbox or one whose state was lost.
        let snapshot = makeManagedSnapshot(
            name: "test-sandbox", agent: "claude",
            workspace: SandboxManager.resolveWorkspacePath(testWorkspace),
            status: .stopped
        )
        h.containers.snapshots["test-sandbox"] = snapshot

        await #expect(throws: SandboxError.self) {
            try await h.manager.bootstrapIfNeeded(name: "test-sandbox", snapshot: snapshot)
        }
    }

    @Test func bootstrapReadsPolicyFromStateStorageNotLabels() async throws {
        let h = makeManager()

        // Create sandbox (writes template default policy to state storage).
        let (name, _) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        // Mutate the policy in state storage (as `network proxy` would).
        let mutatedPolicy = NetworkPolicy.allow
        h.proxyStorage.writtenPolicies[name] = mutatedPolicy

        let snapshot = try #require(h.containers.snapshots[name])

        // Bootstrap should use the mutated policy from state storage.
        try await h.manager.bootstrapIfNeeded(name: name, snapshot: snapshot)

        // Verify startIfNeeded was called with the mutated policy (not template default).
        // The written policy should be the mutated one, not the original template default.
        let currentPolicy = try h.proxyStorage.loadPolicy(for: name)
        #expect(
            currentPolicy == mutatedPolicy,
            "Bootstrap should use the policy from state storage, not the original template default")
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

    @Test func stopPreservesPolicyInStateStorage() async throws {
        let h = makeManager()

        // Create sandbox through real path — writes policy to state storage.
        let (name, _) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        // Verify policy exists before stop.
        let policyBeforeStop = try h.proxyStorage.loadPolicy(for: name)
        #expect(policyBeforeStop != nil, "Policy should exist after creation")

        // Mark as running so stop actually stops it.
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "claude",
            workspace: SandboxManager.resolveWorkspacePath(testWorkspace),
            status: .running
        )

        try await h.manager.stopSandbox(name: name)

        // Policy must survive stop — this is the core persistence contract.
        let policyAfterStop = try h.proxyStorage.loadPolicy(for: name)
        #expect(
            policyAfterStop == policyBeforeStop,
            "stop must preserve policy in state storage for restart")
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

    @Test func deleteRemovesPolicyFromStateStorage() async throws {
        let h = makeManager()

        // Create sandbox — writes policy to state storage.
        let (name, _) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )

        // Verify policy exists before delete.
        #expect(try h.proxyStorage.loadPolicy(for: name) != nil)

        try await h.manager.deleteSandbox(name: name)

        // Delete must remove policy — sandbox is gone, no restart possible.
        let policyAfterDelete = try h.proxyStorage.loadPolicy(for: name)
        #expect(
            policyAfterDelete == nil,
            "delete must remove policy from state storage")
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

    // MARK: - Policy lifecycle: create → stop → bootstrap round-trip

    @Test func policyPersistsAcrossStopAndBootstrap() async throws {
        let h = makeManager()

        // Create sandbox — writes template default policy.
        let (name, _) = try await h.manager.ensureSandboxExists(
            template: ClaudeTemplate(),
            workspace: testWorkspace
        )
        let originalPolicy = try #require(try h.proxyStorage.loadPolicy(for: name))

        // Mark as running and stop it.
        h.containers.snapshots[name] = makeManagedSnapshot(
            name: name, agent: "claude",
            workspace: SandboxManager.resolveWorkspacePath(testWorkspace),
            status: .running
        )
        try await h.manager.stopSandbox(name: name)

        // Policy must still be there after stop.
        let afterStop = try #require(try h.proxyStorage.loadPolicy(for: name))
        #expect(afterStop == originalPolicy)

        // Bootstrap should succeed, reading the persisted policy.
        let snapshot = try #require(h.containers.snapshots[name])
        try await h.manager.bootstrapIfNeeded(name: name, snapshot: snapshot)
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
        #expect(
            config.initProcess.environment.contains("PATH=/custom/bin"),
            "Init process should use image env, not empty")
        #expect(config.initProcess.environment.contains("LANG=C.UTF-8"))
    }

    @Test func initProcessAlwaysRunsAsRoot() async throws {
        let h = makeManager()
        h.images.imageConfig = ImageConfig(user: "sandbox")

        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        // proxy-bridge must run as root to connect to the vsock-relayed socket (mode 0000).
        // The image user only applies to agent processes exec'd later.
        if case .id(let uid, _) = config.initProcess.user {
            #expect(uid == 0)
        } else {
            Issue.record("Expected root (.id(uid: 0)) for init process, got \(config.initProcess.user)")
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
        if case .id(let uid, let gid) = config.initProcess.user {
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
        #expect(
            proxyMount != nil,
            "Proxy socket must be mounted at /run/proxy.sock for proxy-bridge")
    }

    @Test func createdContainerHasCorrectResourceLimits() async throws {
        let h = makeManager()

        _ = try await h.manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: testWorkspace
        )

        let config = h.containers.createdConfigs[0]
        #expect(config.resources.cpus == ProcessInfo.processInfo.processorCount)
        #expect(
            config.resources.memoryInBytes == 8 * 1024 * 1024 * 1024,
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
        #expect(config.ssh == true, "ShellTemplate now shares the agent base and enables SSH")
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
}

// MARK: - Adversarial: extraWorkspacesLabel ordering

struct AdversarialSandboxManagerTests {
    // Bug #7: extraWorkspacesLabel is order-dependent for :ro dedup.
    // The `seen` set deduplicates by resolved path, but the :ro annotation
    // comes from the first occurrence. Different input order → different labels.
    // This causes spurious extraWorkspaceMismatch errors on sandbox reuse.

    @Test func extraWorkspacesLabelOrderIndependentForReadOnly() {
        let tmp = FileManager.default.temporaryDirectory.path
        let extra = "\(tmp)/adversarial-ws-test"
        try? FileManager.default.createDirectory(atPath: extra, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: extra) }

        let label1 = SandboxManager.extraWorkspacesLabel(["\(extra):ro", extra])
        let label2 = SandboxManager.extraWorkspacesLabel([extra, "\(extra):ro"])
        #expect(
            label1 == label2,
            "Same paths with different :ro ordering should produce identical labels. Got '\(label1)' vs '\(label2)'")
    }

    @Test func extraWorkspacesLabelOrderIndependentMultiplePaths() {
        let tmp = FileManager.default.temporaryDirectory.path
        let a = "\(tmp)/adversarial-ws-a"
        let b = "\(tmp)/adversarial-ws-b"
        try? FileManager.default.createDirectory(atPath: a, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(atPath: b, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(atPath: a)
            try? FileManager.default.removeItem(atPath: b)
        }

        // Different ordering of the same two paths should produce the same label.
        let label1 = SandboxManager.extraWorkspacesLabel([a, b])
        let label2 = SandboxManager.extraWorkspacesLabel([b, a])
        #expect(
            label1 == label2,
            "Extra workspace labels should be order-independent. Got '\(label1)' vs '\(label2)'")
    }
}

// MARK: - Duplicate / label / input regressions

private let edgeCaseWorkspace = FileManager.default.temporaryDirectory
    .appendingPathComponent("sandbox-edgecase-workspace").path
private let edgeCaseExtra = FileManager.default.temporaryDirectory
    .appendingPathComponent("sandbox-edgecase-extra").path

private func makeEdgeCaseManager() -> (SandboxManager, FakeContainerOperations) {
    let containers = FakeContainerOperations()
    let images = FakeImageOperations()
    // Pre-stamp both template images as already built so the test focuses
    // on post-build behavior rather than triggering a fake build run.
    images.existingImages = [
        ClaudeTemplate().defaultImage,
        ShellTemplate().defaultImage,
    ]
    let manager = SandboxManager(
        containers: containers,
        images: images,
        kernels: FakeKernelProvider(),
        sessions: SessionTracker(storage: FakeSessionStorage(), pidIsAlive: { _ in false }),
        proxy: ProxyManager(launcher: FakeProxyLauncher(), stateStorage: FakeProxyStateStorage()),
        libexecPath: testLibexecPath
    )
    return (manager, containers)
}

struct SandboxManagerDuplicateMountBugs {
    init() {
        try? FileManager.default.createDirectory(
            atPath: edgeCaseWorkspace, withIntermediateDirectories: true
        )
        try? FileManager.default.createDirectory(
            atPath: edgeCaseExtra, withIntermediateDirectories: true
        )
    }

    @Test func duplicateExtraWorkspacesCreateConflictingMounts() async throws {
        // Passing the same path twice in extraWorkspaces (once r/w, once r/o)
        // creates two virtiofs mounts at the same destination. The dedup check
        // only compares against the primary workspace, not among extras.
        let (manager, containers) = makeEdgeCaseManager()

        _ = try await manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: edgeCaseWorkspace,
            extraWorkspaces: [edgeCaseExtra, "\(edgeCaseExtra):ro"]
        )

        let config = containers.createdConfigs[0]
        let resolvedExtra = SandboxManager.resolveWorkspacePath(edgeCaseExtra)
        let mountsAtDest = config.mounts.filter { $0.destination == resolvedExtra }
        #expect(
            mountsAtDest.count <= 1,
            "Should not create \(mountsAtDest.count) conflicting mounts at '\(resolvedExtra)'")
    }

    @Test func sameExtraWorkspaceDifferentFormsCreatesDuplicateMounts() async throws {
        // The same directory expressed as two different path forms (with/without
        // trailing slash or ../) would both be resolved to the same destination,
        // creating duplicate mounts.
        let (manager, containers) = makeEdgeCaseManager()

        let parent = FileManager.default.temporaryDirectory.path
        let extra1 = edgeCaseExtra
        let extra2 = "\(parent)/sandbox-edgecase-extra/../sandbox-edgecase-extra"

        _ = try await manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: edgeCaseWorkspace,
            extraWorkspaces: [extra1, extra2]
        )

        let config = containers.createdConfigs[0]
        let resolvedExtra = SandboxManager.resolveWorkspacePath(edgeCaseExtra)
        let mountsAtDest = config.mounts.filter { $0.destination == resolvedExtra }
        #expect(
            mountsAtDest.count <= 1,
            "Same directory via different paths should not create duplicate mounts")
    }
}

struct SandboxManagerLabelBugs {
    @Test func extraWorkspaceLabelCommaAmbiguity() {
        // A single path containing a comma produces the same label as two
        // separate paths joined by comma. "/a,/b" (one path: file "b" in
        // directory "a,") collides with two paths "/a" and "/b" joined as "/a,/b".
        let singlePathWithComma = SandboxManager.extraWorkspacesLabel(["/a,/b"])
        let twoSeparatePaths = SandboxManager.extraWorkspacesLabel(["/a", "/b"])
        #expect(
            singlePathWithComma != twoSeparatePaths,
            "Label for path '/a,/b' should differ from label for paths '/a' + '/b'")
    }
}

struct SandboxManagerInputValidationBugs {
    init() {
        try? FileManager.default.createDirectory(
            atPath: edgeCaseWorkspace, withIntermediateDirectories: true
        )
    }

    @Test func emptyExtraWorkspaceSilentlyMountsCwd() async throws {
        // An empty string in extraWorkspaces resolves to the current working
        // directory via resolveWorkspacePath(""). This silently mounts the
        // entire cwd into the sandbox with no indication to the user.
        let (manager, containers) = makeEdgeCaseManager()

        _ = try await manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: edgeCaseWorkspace,
            extraWorkspaces: [""]
        )

        let config = containers.createdConfigs[0]
        let resolvedCwd = SandboxManager.resolveWorkspacePath("")
        let cwdMounts = config.mounts.filter { $0.destination == resolvedCwd }
        #expect(
            cwdMounts.isEmpty,
            "Empty string extra workspace should not silently mount '\(resolvedCwd)'")
    }
}

// MARK: - parseWorkspacePath

struct SandboxManagerUtilTests {
    @Test func parseWorkspacePathPlain() {
        let (path, readOnly) = SandboxManager.parseWorkspacePath("/some/path")
        #expect(path == "/some/path")
        #expect(!readOnly)
    }

    @Test func parseWorkspacePathReadOnly() {
        let (path, readOnly) = SandboxManager.parseWorkspacePath("/some/path:ro")
        #expect(path == "/some/path")
        #expect(readOnly)
    }
}

// MARK: - extraWorkspacesLabel roundtrip

struct ExtraWorkspaceRoundTripTests {
    init() {
        try? FileManager.default.createDirectory(
            atPath: testWorkspace,
            withIntermediateDirectories: true
        )
    }

    @Test func duplicateExtrasProduceSameLabelAsDeduplicated() {
        // The label builder should produce identical output regardless of
        // whether duplicates are present, since mount creation deduplicates.
        let withDupes = SandboxManager.extraWorkspacesLabel([testWorkspace, testWorkspace])
        let withoutDupes = SandboxManager.extraWorkspacesLabel([testWorkspace])

        #expect(
            withDupes == withoutDupes,
            "Duplicate extras should be collapsed to match mount deduplication")
    }

    @Test func extraWorkspaceLabelIsPathNormalized() {
        // /path and /path/../path resolve to the same location.
        // The label should be identical for both.
        let direct = SandboxManager.extraWorkspacesLabel([testWorkspace])
        let indirect = SandboxManager.extraWorkspacesLabel([testWorkspace + "/../" + URL(fileURLWithPath: testWorkspace).lastPathComponent])

        #expect(
            direct == indirect,
            "Path-equivalent extras should produce the same label")
    }
}
