import ContainerAPIClient
import ContainerizationError
import ContainerizationOCI
import ContainerResource
import Foundation
import Logging

private let log = Logger(label: "container-sandbox")

/// Label keys used to tag sandbox containers.
enum SandboxLabels {
    static let managed = "sandbox.managed"
    static let agent = "sandbox.agent"
    static let workspace = "sandbox.workspace"
    static let extraWorkspaces = "sandbox.extra-workspaces"
    static let imageUser = "sandbox.image-user"
}

/// Manages sandbox lifecycle using injectable container, image, and kernel operations.
struct SandboxManager {
    let containers: any ContainerOperations
    let images: any ImageOperations
    let kernels: any KernelProvider
    let sessions: SessionTracker
    let proxy: ProxyManager
    let libexecPath: String

    init(
        containers: any ContainerOperations = LiveContainerOperations(),
        images: any ImageOperations = LiveImageOperations(),
        kernels: any KernelProvider = LiveKernelProvider(),
        sessions: SessionTracker = SessionTracker(),
        proxy: ProxyManager = ProxyManager(),
        libexecPath: String = defaultLibexecPath
    ) {
        self.containers = containers
        self.images = images
        self.kernels = kernels
        self.sessions = sessions
        self.proxy = proxy
        self.libexecPath = libexecPath
    }

    // MARK: - Listing

    func listSandboxes() async throws -> [ContainerSnapshot] {
        let all = try await containers.list()
        return all.filter { $0.configuration.labels[SandboxLabels.managed] == "true" }
    }

    /// Get a specific sandbox by ID. Returns nil if not found.
    func getSandbox(name: String) async throws -> ContainerSnapshot? {
        do {
            return try await containers.get(id: name)
        } catch let error as ContainerizationError where error.code == .notFound {
            return nil
        }
    }

    // MARK: - Image Management

    func buildImageIfNeeded(template: any AgentTemplate) async throws {
        if try await images.imageExists(reference: template.defaultImage) {
            return
        }
        guard let containerfileContent = template.containerfileContent else {
            return
        }
        try await images.buildImage(tag: template.defaultImage, containerfileContent: containerfileContent)
    }

    // MARK: - Creation

    /// Ensure a sandbox exists for the given agent + workspace. Creates if missing.
    /// Returns the sandbox name and its snapshot.
    func ensureSandboxExists(
        template: any AgentTemplate,
        workspace: String,
        extraWorkspaces: [String] = [],
        nameOverride: String? = nil
    ) async throws -> (name: String, snapshot: ContainerSnapshot) {
        let resolvedWorkspace = Self.resolveWorkspacePath(workspace)

        guard FileManager.default.fileExists(atPath: resolvedWorkspace) else {
            throw SandboxError.workspaceNotFound(resolvedWorkspace)
        }

        let name = nameOverride ?? SandboxNaming.sandboxName(agent: template.name, workspacePath: resolvedWorkspace)
        try SandboxNaming.validateName(name)

        if let existing = try await getSandbox(name: name) {
            let labels = existing.configuration.labels

            // Verify workspace matches.
            let existingWorkspace = labels[SandboxLabels.workspace] ?? ""
            if existingWorkspace != resolvedWorkspace {
                throw SandboxError.workspaceMismatch(
                    name: name,
                    existing: existingWorkspace,
                    requested: resolvedWorkspace
                )
            }
            // Verify agent matches.
            let existingAgent = labels[SandboxLabels.agent] ?? ""
            if existingAgent != template.name {
                throw SandboxError.agentMismatch(
                    name: name,
                    existing: existingAgent,
                    requested: template.name
                )
            }
            // Verify extra workspace mounts match.
            let requestedLabel = Self.extraWorkspacesLabel(extraWorkspaces)
            let existingLabel = labels[SandboxLabels.extraWorkspaces] ?? ""
            if existingLabel != requestedLabel {
                throw SandboxError.extraWorkspaceMismatch(name: name)
            }
            return (name, existing)
        }

        let platform: ContainerizationOCI.Platform = .current

        try await buildImageIfNeeded(template: template)

        // Kernel fetch is independent of image setup — overlap them.
        async let kernel = kernels.getDefaultKernel()

        let imageDesc = try await images.prepareImage(reference: template.defaultImage, platform: platform)
        let imageConfig = try await images.getImageConfig(reference: template.defaultImage, platform: platform)

        let initProcess = ProcessConfiguration(
            executable: "/opt/sandbox/proxy-bridge",
            arguments: [],
            environment: imageConfig?.env ?? [],
            workingDirectory: imageConfig?.workingDir ?? "/",
            // proxy-bridge must run as root to connect to the vsock-relayed socket
            // (created with mode 0000). Agent processes exec'd later use the image user.
            user: .id(uid: 0, gid: 0)
        )

        var config = ContainerConfiguration(
            id: name,
            image: imageDesc,
            process: initProcess
        )

        config.mounts.append(
            .virtiofs(source: resolvedWorkspace, destination: resolvedWorkspace, options: [])
        )

        var mountedPaths: Set<String> = [resolvedWorkspace]
        for extra in extraWorkspaces {
            let (path, readOnly) = Self.parseWorkspacePath(extra)
            guard !path.isEmpty else { continue }
            let resolved = Self.resolveWorkspacePath(path)
            guard FileManager.default.fileExists(atPath: resolved) else {
                throw SandboxError.workspaceNotFound(resolved)
            }
            guard mountedPaths.insert(resolved).inserted else { continue }
            config.mounts.append(
                .virtiofs(source: resolved, destination: resolved, options: readOnly ? ["ro"] : [])
            )
        }

        // Mount proxy-bridge binary into the container (virtiofs shares directories, not files).
        guard FileManager.default.fileExists(atPath: libexecPath + "/proxy-bridge") else {
            throw SandboxError.proxyBridgeMissing
        }
        config.mounts.append(
            .virtiofs(source: libexecPath, destination: "/opt/sandbox", options: ["ro"])
        )

        // Mount proxy socket into the container.
        // The framework auto-detects socket mounts and relays via vsock (.into direction).
        let socketPath = try await proxy.startIfNeeded(name: name, policy: template.defaultNetworkPolicy)
        config.mounts.append(
            .virtiofs(source: socketPath, destination: "/run/proxy.sock", options: [])
        )

        // Store the image user so agent processes can run as the correct user
        // (the init process runs as root for socket access, not the image user).
        let imageUser = imageConfig?.user.flatMap { $0.isEmpty ? nil : $0 } ?? ""

        config.labels = [
            SandboxLabels.managed: "true",
            SandboxLabels.agent: template.name,
            SandboxLabels.workspace: resolvedWorkspace,
            SandboxLabels.extraWorkspaces: Self.extraWorkspacesLabel(extraWorkspaces),
            SandboxLabels.imageUser: imageUser,
        ]

        config.ssh = template.requiresSSH
        config.virtualization = template.requiresVirtualization
        config.useInit = template.useInit
        config.resources.cpus = ProcessInfo.processInfo.processorCount
        config.resources.memoryInBytes = 8 * 1024 * 1024 * 1024

        try await containers.create(configuration: config, options: ContainerCreateOptions.default, kernel: await kernel, initImage: nil)

        let snapshot = try await containers.get(id: name)
        return (name, snapshot)
    }

    // MARK: - Lifecycle

    func bootstrapIfNeeded(name: String, snapshot _: ContainerSnapshot) async throws {
        // Policy lives exclusively in proxy state storage.
        guard let policy = try proxy.stateStorage.loadPolicy(for: name) else {
            throw SandboxError.outdatedSandbox(name)
        }

        // Always ensure proxy is running with current policy.
        try await proxy.startIfNeeded(name: name, policy: policy)

        // Re-fetch status to avoid racing with another process that may have
        // already started this container between the caller's snapshot and now.
        let current = try await containers.get(id: name)
        if current.status == RuntimeStatus.running {
            return
        }

        let io = try ProcessIO.create(tty: false, interactive: false, detach: true)
        defer { try? io.close() }

        let process = try await containers.bootstrap(id: name, stdio: io.stdio)
        try await process.start()
        try io.closeAfterStart()
    }

    func runProcess(
        name: String,
        configuration: ProcessConfiguration
    ) async throws -> Int32 {
        let io = try ProcessIO.create(tty: configuration.terminal, interactive: configuration.terminal, detach: false)
        defer { try? io.close() }

        let process = try await containers.createProcess(
            containerId: name,
            processId: UUID().uuidString.lowercased(),
            configuration: configuration,
            stdio: io.stdio
        )

        return try await io.handleProcess(process: process, log: log)
    }

    /// Run a process with session tracking. Auto-stops the sandbox when the last session exits.
    func runTracked(
        name: String,
        configuration: ProcessConfiguration
    ) async throws -> Int32 {
        let sessionId = try sessions.create(for: name)
        let exitCode: Int32
        do {
            exitCode = try await runProcess(name: name, configuration: configuration)
        } catch {
            let wasLast = sessions.remove(sessionId: sessionId, for: name)
            if wasLast { try? await stopSandbox(name: name) }
            throw error
        }
        let wasLast = sessions.remove(sessionId: sessionId, for: name)
        if wasLast { try? await stopSandbox(name: name) }
        return exitCode
    }

    /// Stop a sandbox. Returns `true` if a container was actually stopped,
    /// `false` if it was already gone (stale host state is cleaned up either way).
    @discardableResult
    func stopSandbox(name: String) async throws -> Bool {
        // Always clean up host-side resources, even if the container was
        // deleted externally (e.g. via `container rm` instead of `sandbox rm`).
        defer {
            sessions.clearAll(for: name)
            proxy.stop(name: name)
        }
        guard let snapshot = try await getSandbox(name: name) else {
            // Container already gone — defer handles host-side cleanup.
            return false
        }
        guard snapshot.configuration.labels[SandboxLabels.managed] == "true" else {
            throw SandboxError.notManagedSandbox(name)
        }
        try await containers.stop(id: name)
        return true
    }

    /// Delete a sandbox. Returns `true` if a container was actually deleted,
    /// `false` if it was already gone (stale host state is cleaned up either way).
    @discardableResult
    func deleteSandbox(name: String) async throws -> Bool {
        var found = false
        if let snapshot = try await getSandbox(name: name) {
            guard snapshot.configuration.labels[SandboxLabels.managed] == "true" else {
                throw SandboxError.notManagedSandbox(name)
            }
            if snapshot.status == .running {
                try await containers.stop(id: name)
            }
            try await containers.delete(id: name)
            found = true
        }
        // Clean up host-side resources after container is gone.
        sessions.clearAll(for: name)
        proxy.stop(name: name)
        proxy.stateStorage.removeAll(for: name)
        return found
    }

    func exportSandbox(name: String, to path: String) async throws {
        try await containers.export(id: name, archive: URL(fileURLWithPath: path))
    }

    /// Load the network policy for a sandbox from state storage.
    func getPolicy(for name: String) throws -> NetworkPolicy? {
        try proxy.stateStorage.loadPolicy(for: name)
    }

    // MARK: - Paths

    /// Default host directory containing helper binaries mounted into containers.
    /// Must match STABLE_DIR/libexec in the Makefile.
    static let defaultLibexecPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/lib/container-sandbox/libexec").path

    // MARK: - Utilities

    /// Build a canonical label value for extra workspaces.
    /// Resolves paths, sorts, and joins so reuse checks are order-independent.
    static func extraWorkspacesLabel(_ extras: [String]) -> String {
        var seen = Set<String>()
        return extras.compactMap { input in
            let (path, readOnly) = parseWorkspacePath(input)
            guard !path.isEmpty else { return nil }
            let resolved = resolveWorkspacePath(path)
            guard seen.insert(resolved).inserted else { return nil }
            return readOnly ? "\(resolved):ro" : resolved
        }.sorted().joined(separator: "\n")
    }

    /// Build an exec environment from a container's init config with last-writer-wins dedup.
    /// Layers: base env < TERM (if tty) < extras < proxy vars.
    static func execEnvironment(base: [String], extras: [String] = [], tty: Bool = false) -> [String] {
        var envMap: [(key: String, value: String)] = []
        for entry in base {
            if let (k, v) = parseEnvEntry(entry) {
                envMap.append((k, v))
            }
        }
        if tty {
            envMap.append(("TERM", "xterm-256color"))
        }
        for entry in extras {
            if let (k, v) = parseEnvEntry(entry) {
                envMap.append((k, v))
            }
        }
        for entry in ProxyManager.proxyEnvironment {
            envMap.append(entry)
        }
        return deduplicateEnvironment(envMap)
    }

    static func resolveWorkspacePath(_ path: String) -> String {
        URL(fileURLWithPath: path, relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)).standardized.path
    }

    static func parseWorkspacePath(_ input: String) -> (path: String, readOnly: Bool) {
        if input.hasSuffix(":ro") {
            return (String(input.dropLast(3)), true)
        }
        return (input, false)
    }
}
