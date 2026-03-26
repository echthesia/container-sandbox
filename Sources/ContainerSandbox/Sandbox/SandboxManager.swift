import ContainerAPIClient
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
    static let direction = "sandbox.direction"
    static let allowedHosts = "sandbox.allowed-hosts"
    static let blockedHosts = "sandbox.blocked-hosts"
    static let blockedCIDRs = "sandbox.blocked-cidrs"
}

/// Manages sandbox lifecycle using the ContainerClient API.
struct SandboxManager {
    let client: ContainerClient

    init() {
        client = ContainerClient()
    }

    // MARK: - Listing

    func listSandboxes() async throws -> [ContainerSnapshot] {
        let all = try await client.list()
        return all.filter { SandboxNaming.isSandboxName($0.id) }
    }

    /// Get a specific sandbox by ID. Returns nil if not found.
    func getSandbox(name: String) async throws -> ContainerSnapshot? {
        // Use direct get instead of listing all containers
        return try? await client.get(id: name)
    }

    // MARK: - Image Management

    func buildImageIfNeeded(template: any AgentTemplate) async throws {
        if let _ = try? await ClientImage.get(reference: template.defaultImage) {
            return
        }

        guard let containerfileContent = template.containerfileContent else {
            return
        }

        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("container-sandbox-build-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let containerfilePath = tmpDir.appendingPathComponent("Containerfile")
        try containerfileContent.write(to: containerfilePath, atomically: true, encoding: .utf8)

        print("Building image \(template.defaultImage)...")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "container", "build",
            "--tag", template.defaultImage,
            "--file", containerfilePath.path,
            "--progress", "plain",
            "--memory", "8G",
            tmpDir.path,
        ]
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError

        let status = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int32, any Error>) in
            process.terminationHandler = { p in
                continuation.resume(returning: p.terminationStatus)
            }
            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }

        guard status == 0 else {
            throw SandboxError.imageBuildFailed("container build exited with status \(status)")
        }
    }

    // MARK: - Creation

    /// Ensure a sandbox exists for the given agent + workspace. Creates if missing.
    /// Returns the sandbox name and its snapshot.
    func ensureSandboxExists(
        template: any AgentTemplate,
        workspace: String,
        extraWorkspaces: [String] = [],
        networkPolicy: NetworkPolicy = .allow,
        nameOverride: String? = nil
    ) async throws -> (name: String, snapshot: ContainerSnapshot) {
        let resolvedWorkspace = Self.resolveWorkspacePath(workspace)

        guard FileManager.default.fileExists(atPath: resolvedWorkspace) else {
            throw SandboxError.workspaceNotFound(resolvedWorkspace)
        }

        let name = nameOverride ?? SandboxNaming.sandboxName(agent: template.name, workspacePath: resolvedWorkspace)

        if let existing = try await getSandbox(name: name) {
            // Verify the existing sandbox's network policy matches what was requested.
            guard let existingPolicy = NetworkPolicy.fromLabels(existing.configuration.labels) else {
                throw SandboxError.outdatedSandbox(name)
            }
            if existingPolicy != networkPolicy {
                throw SandboxError.networkPolicyMismatch(
                    name: name,
                    existing: existingPolicy,
                    requested: networkPolicy
                )
            }
            // Verify extra workspace mounts match.
            let requestedLabel = Self.extraWorkspacesLabel(extraWorkspaces)
            let existingLabel = existing.configuration.labels[SandboxLabels.extraWorkspaces] ?? ""
            if existingLabel != requestedLabel {
                throw SandboxError.extraWorkspaceMismatch(name: name)
            }
            return (name, existing)
        }

        let platform: ContainerizationOCI.Platform = .current

        try await buildImageIfNeeded(template: template)

        // Kernel fetch is independent of image setup — overlap them.
        async let kernel = ClientKernel.getDefaultKernel(for: .current)

        let img = try await ClientImage.fetch(reference: template.defaultImage, platform: platform)
        try await img.getCreateSnapshot(platform: platform)

        let imageConfig = try await img.config(for: platform).config

        let initProcess = ProcessConfiguration(
            executable: "/bin/sleep",
            arguments: ["infinity"],
            environment: imageConfig?.env ?? [],
            workingDirectory: imageConfig?.workingDir ?? "/",
            user: imageConfig?.user.flatMap { $0.isEmpty ? nil : $0 }.map { .raw(userString: $0) } ?? .id(uid: 0, gid: 0)
        )

        var config = ContainerConfiguration(
            id: name,
            image: img.description,
            process: initProcess
        )

        config.mounts.append(
            .virtiofs(source: resolvedWorkspace, destination: resolvedWorkspace, options: [])
        )

        for extra in extraWorkspaces {
            let (path, readOnly) = Self.parseWorkspacePath(extra)
            let resolved = Self.resolveWorkspacePath(path)
            guard FileManager.default.fileExists(atPath: resolved) else {
                throw SandboxError.workspaceNotFound(resolved)
            }
            config.mounts.append(
                .virtiofs(source: resolved, destination: resolved, options: readOnly ? ["ro"] : [])
            )
        }

        // Always start proxy and mount its UDS into the VM.
        // The framework auto-detects socket mounts and relays via vsock (.into direction).
        let socketPath = try await ProxyManager.startIfNeeded(name: name, policy: networkPolicy)
        config.mounts.append(
            .virtiofs(source: socketPath, destination: "/run/proxy.sock", options: [])
        )

        config.labels = [
            SandboxLabels.managed: "true",
            SandboxLabels.agent: template.name,
            SandboxLabels.workspace: resolvedWorkspace,
            SandboxLabels.extraWorkspaces: Self.extraWorkspacesLabel(extraWorkspaces),
            SandboxLabels.direction: networkPolicy.direction.rawValue,
            SandboxLabels.allowedHosts: networkPolicy.allowedHostsLabel,
            SandboxLabels.blockedHosts: networkPolicy.blockedHostsLabel,
            SandboxLabels.blockedCIDRs: networkPolicy.blockedCIDRsLabel,
        ]

        config.ssh = template.requiresSSH
        config.virtualization = template.requiresVirtualization
        config.useInit = template.useInit
        config.resources.cpus = ProcessInfo.processInfo.processorCount
        config.resources.memoryInBytes = 8 * 1024 * 1024 * 1024

        // Always use custom init image (contains the proxy bridge).
        let customInitRef = "container-sandbox-init:latest"
        guard let _ = try? await ClientImage.get(reference: customInitRef) else {
            throw SandboxError.initImageMissing
        }
        let customInit = try await ClientImage.fetch(reference: customInitRef, platform: .current)
        try await customInit.getCreateSnapshot(platform: .current)

        try await client.create(configuration: config, options: .default, kernel: await kernel, initImage: customInitRef)

        let snapshot = try await client.get(id: name)
        return (name, snapshot)
    }

    // MARK: - Lifecycle

    func bootstrapIfNeeded(name: String, snapshot: ContainerSnapshot) async throws {
        // Detect old-format sandboxes missing the direction label.
        guard let policy = NetworkPolicy.fromLabels(snapshot.configuration.labels) else {
            throw SandboxError.outdatedSandbox(name)
        }

        // Always ensure proxy is running with current policy from labels.
        try await ProxyManager.startIfNeeded(name: name, policy: policy)

        if snapshot.status == .running {
            return
        }

        let io = try ProcessIO.create(tty: false, interactive: false, detach: true)
        defer { try? io.close() }

        let process = try await client.bootstrap(id: name, stdio: io.stdio)
        try await process.start()
        try io.closeAfterStart()
    }

    func runProcess(
        name: String,
        configuration: ProcessConfiguration
    ) async throws -> Int32 {
        let io = try ProcessIO.create(tty: configuration.terminal, interactive: configuration.terminal, detach: false)
        defer { try? io.close() }

        let process = try await client.createProcess(
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
        let sessionId = try SessionTracker.create(for: name)
        let exitCode: Int32
        do {
            exitCode = try await runProcess(name: name, configuration: configuration)
        } catch {
            let wasLast = SessionTracker.remove(sessionId: sessionId, for: name)
            if wasLast { try? await stopSandbox(name: name) }
            throw error
        }
        let wasLast = SessionTracker.remove(sessionId: sessionId, for: name)
        if wasLast { try? await stopSandbox(name: name) }
        return exitCode
    }

    func stopSandbox(name: String) async throws {
        SessionTracker.clearAll(for: name)
        ProxyManager.stop(name: name)
        try await client.stop(id: name)
    }

    func deleteSandbox(name: String) async throws {
        SessionTracker.clearAll(for: name)
        ProxyManager.stop(name: name)
        let snapshot = try await client.get(id: name)
        if snapshot.status == .running {
            try await client.stop(id: name)
        }
        try await client.delete(id: name)
    }

    func exportSandbox(name: String, to path: String) async throws {
        try await client.export(id: name, archive: URL(fileURLWithPath: path))
    }

    // MARK: - Utilities

    /// Build a canonical label value for extra workspaces.
    /// Resolves paths, sorts, and joins so reuse checks are order-independent.
    static func extraWorkspacesLabel(_ extras: [String]) -> String {
        extras.map { input in
            let (path, readOnly) = parseWorkspacePath(input)
            let resolved = resolveWorkspacePath(path)
            return readOnly ? "\(resolved):ro" : resolved
        }.sorted().joined(separator: ",")
    }

    /// Build an exec environment from a container's init config with last-writer-wins dedup.
    /// Layers: base env < extras < TERM < proxy vars.
    static func execEnvironment(base: [String], extras: [String] = []) -> [String] {
        var envMap: [(key: String, value: String)] = []
        for entry in base {
            if let (k, v) = parseEnvEntry(entry) {
                envMap.append((k, v))
            }
        }
        envMap.append(("TERM", "xterm-256color"))
        for entry in extras {
            if let (k, v) = parseEnvEntry(entry) {
                envMap.append((k, v))
            }
        }
        for entry in ProxyManager.proxyEnvironment {
            envMap.append(entry)
        }
        var seen = Set<String>()
        var env: [String] = []
        for (key, value) in envMap.reversed() {
            if seen.insert(key).inserted {
                env.append("\(key)=\(value)")
            }
        }
        env.reverse()
        return env
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
