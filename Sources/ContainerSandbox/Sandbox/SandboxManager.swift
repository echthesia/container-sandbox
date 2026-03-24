import ContainerAPIClient
import ContainerResource
import ContainerizationOCI
import Foundation
import Logging

private let log = Logger(label: "container-sandbox")

/// Manages sandbox lifecycle using the ContainerClient API.
struct SandboxManager: Sendable {
    let client: ContainerClient

    init() {
        self.client = ContainerClient()
    }

    // MARK: - Listing

    /// List all sandbox containers (filtered by naming convention).
    func listSandboxes() async throws -> [ContainerSnapshot] {
        let all = try await client.list()
        return all.filter { SandboxNaming.isSandboxName($0.id) }
    }

    /// Get a specific sandbox by name, or nil if it doesn't exist.
    func getSandbox(name: String) async throws -> ContainerSnapshot? {
        let sandboxes = try await listSandboxes()
        return sandboxes.first { $0.id == name }
    }

    // MARK: - Creation

    /// Ensure a sandbox exists for the given agent + workspace. Creates if missing.
    /// Reads the OCI image config for user, env, entrypoint — matching native CLI behavior.
    func ensureSandboxExists(
        template: any AgentTemplate,
        workspace: String
    ) async throws -> String {
        let resolvedWorkspace = URL(fileURLWithPath: workspace, relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)).standardized.path

        guard FileManager.default.fileExists(atPath: resolvedWorkspace) else {
            throw SandboxError.workspaceNotFound(resolvedWorkspace)
        }

        let name = SandboxNaming.sandboxName(agent: template.name, workspacePath: resolvedWorkspace)

        if let _ = try await getSandbox(name: name) {
            return name
        }

        let platform: ContainerizationOCI.Platform = .current

        // Fetch and unpack the image
        let img = try await ClientImage.fetch(reference: template.defaultImage, platform: platform)
        try await img.getCreateSnapshot(platform: platform)

        // Get kernel
        let kernel = try await ClientKernel.getDefaultKernel(for: .current)

        // Fetch and unpack the init image
        let initImageRef = ClientImage.initImageRef
        let initImage = try await ClientImage.fetch(reference: initImageRef, platform: .current)
        try await initImage.getCreateSnapshot(platform: .current)

        // Read the OCI image config for user, env, entrypoint, workdir
        let imageConfig = try await img.config(for: platform).config

        let imageEnv = imageConfig?.env ?? []
        let imageWorkdir = imageConfig?.workingDir ?? "/"
        let imageUser: ProcessConfiguration.User = {
            if let user = imageConfig?.user, !user.isEmpty {
                return .raw(userString: user)
            }
            return .id(uid: 0, gid: 0)
        }()

        // Build init process from image defaults
        let initProcess = ProcessConfiguration(
            executable: "/bin/sleep",
            arguments: ["infinity"],
            environment: imageEnv,
            workingDirectory: imageWorkdir,
            user: imageUser
        )

        var config = ContainerConfiguration(
            id: name,
            image: img.description,
            process: initProcess
        )

        // Mount workspace at the same absolute path
        config.mounts.append(
            .virtiofs(source: resolvedWorkspace, destination: resolvedWorkspace, options: [])
        )

        // Labels
        config.labels = [
            "sandbox.managed": "true",
            "sandbox.agent": template.name,
            "sandbox.workspace": resolvedWorkspace,
        ]

        // Template flags
        config.ssh = template.requiresSSH
        config.virtualization = template.requiresVirtualization
        config.useInit = template.useInit

        // Resources
        config.resources.cpus = ProcessInfo.processInfo.processorCount
        config.resources.memoryInBytes = 4 * 1024 * 1024 * 1024 // 4 GiB

        try await client.create(configuration: config, options: .default, kernel: kernel, initImage: initImageRef)

        return name
    }

    // MARK: - Lifecycle

    /// Bootstrap a sandbox (start it) if it's not already running.
    func bootstrapIfNeeded(name: String) async throws {
        let snapshot = try await client.get(id: name)
        if snapshot.status == .running {
            return
        }

        let io = try ProcessIO.create(tty: false, interactive: false, detach: true)
        defer { try? io.close() }

        let process = try await client.bootstrap(id: name, stdio: io.stdio)
        try await process.start()
        try io.closeAfterStart()
    }

    /// Run a process inside a running sandbox.
    func runProcess(
        name: String,
        configuration: ProcessConfiguration
    ) async throws -> Int32 {
        let tty = configuration.terminal
        let interactive = tty
        let io = try ProcessIO.create(tty: tty, interactive: interactive, detach: false)
        defer { try? io.close() }

        let process = try await client.createProcess(
            containerId: name,
            processId: UUID().uuidString.lowercased(),
            configuration: configuration,
            stdio: io.stdio
        )

        if interactive {
            return try await io.handleProcess(process: process, log: log)
        }

        try await process.start()
        try io.closeAfterStart()
        let exitCode = try await process.wait()
        try await io.wait()
        return exitCode
    }

    /// Stop a sandbox.
    func stopSandbox(name: String) async throws {
        try await client.stop(id: name)
    }

    /// Delete a sandbox (stops first if running).
    func deleteSandbox(name: String) async throws {
        let snapshot = try await client.get(id: name)
        if snapshot.status == .running {
            try await client.stop(id: name)
        }
        try await client.delete(id: name)
    }

    /// Export a sandbox to an archive.
    func exportSandbox(name: String, to path: String) async throws {
        try await client.export(id: name, archive: URL(fileURLWithPath: path))
    }
}
