import ContainerAPIClient
import Containerization
import ContainerizationOCI
import ContainerResource
import Foundation

// MARK: - Protocols

/// Container daemon operations (wraps ContainerClient).
protocol ContainerOperations: Sendable {
    func list() async throws -> [ContainerSnapshot]
    func get(id: String) async throws -> ContainerSnapshot
    func create(configuration: ContainerConfiguration, options: ContainerCreateOptions, kernel: Kernel, initImage: String?) async throws
    func bootstrap(id: String, stdio: [FileHandle?]) async throws -> any ClientProcess
    func createProcess(containerId: String, processId: String, configuration: ProcessConfiguration, stdio: [FileHandle?]) async throws -> any ClientProcess
    func stop(id: String) async throws
    func delete(id: String) async throws
    func export(id: String, archive: URL) async throws
}

/// Image store operations (wraps ClientImage static methods).
protocol ImageOperations: Sendable {
    func imageExists(reference: String) async throws -> Bool
    /// Fetch image, prepare snapshot for container creation, and return its description.
    func prepareImage(reference: String, platform: ContainerizationOCI.Platform) async throws -> ImageDescription
    /// Get the OCI image config (environment, user, working directory).
    func getImageConfig(reference: String, platform: ContainerizationOCI.Platform) async throws -> ContainerizationOCI.ImageConfig?
    /// Build an image from a Containerfile string.
    func buildImage(tag: String, containerfileContent: String) async throws
}

/// Kernel provider (wraps ClientKernel).
protocol KernelProvider: Sendable {
    func getDefaultKernel() async throws -> Kernel
}

// MARK: - Live implementations

/// Forwards to the real ContainerClient.
struct LiveContainerOperations: ContainerOperations {
    private let client = ContainerClient()

    func list() async throws -> [ContainerSnapshot] {
        try await client.list()
    }

    func get(id: String) async throws -> ContainerSnapshot {
        try await client.get(id: id)
    }

    func create(configuration: ContainerConfiguration, options: ContainerCreateOptions, kernel: Kernel, initImage: String?) async throws {
        try await client.create(configuration: configuration, options: options, kernel: kernel, initImage: initImage)
    }

    func bootstrap(id: String, stdio: [FileHandle?]) async throws -> any ClientProcess {
        try await client.bootstrap(id: id, stdio: stdio)
    }

    func createProcess(containerId: String, processId: String, configuration: ProcessConfiguration, stdio: [FileHandle?]) async throws -> any ClientProcess {
        try await client.createProcess(containerId: containerId, processId: processId, configuration: configuration, stdio: stdio)
    }

    func stop(id: String) async throws {
        try await client.stop(id: id)
    }

    func delete(id: String) async throws {
        try await client.delete(id: id)
    }

    func export(id: String, archive: URL) async throws {
        try await client.export(id: id, archive: archive)
    }
}

/// Forwards to ClientImage static methods.
struct LiveImageOperations: ImageOperations {
    func imageExists(reference: String) async throws -> Bool {
        do {
            _ = try await ClientImage.get(reference: reference)
            return true
        } catch {
            return false
        }
    }

    @discardableResult
    func prepareImage(reference: String, platform: ContainerizationOCI.Platform) async throws -> ImageDescription {
        let img = try await ClientImage.fetch(reference: reference, platform: platform)
        try await img.getCreateSnapshot(platform: platform)
        return img.description
    }

    func getImageConfig(reference: String, platform: ContainerizationOCI.Platform) async throws -> ContainerizationOCI.ImageConfig? {
        let img = try await ClientImage.fetch(reference: reference, platform: platform)
        return try await img.config(for: platform).config
    }

    func buildImage(tag: String, containerfileContent: String) async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("container-sandbox-build-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let containerfilePath = tmpDir.appendingPathComponent("Containerfile")
        try containerfileContent.write(to: containerfilePath, atomically: true, encoding: .utf8)

        print("Building image \(tag)...")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "container", "build",
            "--tag", tag,
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
}

/// Forwards to ClientKernel.
struct LiveKernelProvider: KernelProvider {
    func getDefaultKernel() async throws -> Kernel {
        try await ClientKernel.getDefaultKernel(for: .current)
    }
}
