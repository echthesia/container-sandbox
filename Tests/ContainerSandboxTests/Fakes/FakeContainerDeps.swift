import ContainerAPIClient
import Containerization
import ContainerizationError
import ContainerizationOCI
import ContainerizationOS
import ContainerResource
import Foundation
@testable import sandbox

// MARK: - Fake ContainerOperations

final class FakeContainerOperations: ContainerOperations, @unchecked Sendable {
    var snapshots: [String: ContainerSnapshot] = [:]
    var createdConfigs: [ContainerConfiguration] = []
    var stoppedIds: [String] = []
    var deletedIds: [String] = []
    var bootstrappedIds: [String] = []
    var exportedIds: [String] = []

    func list() async throws -> [ContainerSnapshot] {
        Array(snapshots.values)
    }

    func get(id: String) async throws -> ContainerSnapshot {
        guard let snapshot = snapshots[id] else {
            throw ContainerizationError(.notFound, message: "not found: \(id)")
        }
        return snapshot
    }

    func create(configuration: ContainerConfiguration, options _: ContainerCreateOptions, kernel _: Kernel, initImage _: String?) async throws {
        createdConfigs.append(configuration)
        // After creation, the container exists as stopped
        snapshots[configuration.id] = makeSnapshot(config: configuration, status: .stopped)
    }

    func bootstrap(id: String, stdio _: [FileHandle?]) async throws -> any ClientProcess {
        bootstrappedIds.append(id)
        return FakeClientProcess(id: id)
    }

    func createProcess(containerId _: String, processId: String, configuration _: ProcessConfiguration, stdio _: [FileHandle?]) async throws -> any ClientProcess {
        FakeClientProcess(id: processId)
    }

    func stop(id: String) async throws {
        stoppedIds.append(id)
        if let snapshot = snapshots[id] {
            snapshots[id] = makeSnapshot(config: snapshot.configuration, status: .stopped)
        }
    }

    func delete(id: String) async throws {
        deletedIds.append(id)
        snapshots.removeValue(forKey: id)
    }

    func export(id: String, archive _: URL) async throws {
        exportedIds.append(id)
    }
}

// MARK: - Fake ImageOperations

final class FakeImageOperations: ImageOperations, @unchecked Sendable {
    var existingImages: Set<String> = []
    var builtImages: [String] = []
    var imageConfig: ContainerizationOCI.ImageConfig?

    func imageExists(reference: String) async throws -> Bool {
        existingImages.contains(reference)
    }

    @discardableResult
    func prepareImage(reference: String, platform _: ContainerizationOCI.Platform) async throws -> ImageDescription {
        ImageDescription(reference: reference, descriptor: Descriptor(mediaType: "application/vnd.oci.image.manifest.v1+json", digest: "sha256:fake", size: 0))
    }

    func getImageConfig(reference _: String, platform _: ContainerizationOCI.Platform) async throws -> ContainerizationOCI.ImageConfig? {
        imageConfig
    }

    func buildImage(tag: String, containerfileContent _: String) async throws {
        builtImages.append(tag)
        existingImages.insert(tag)
    }
}

// MARK: - Fake KernelProvider

struct FakeKernelProvider: KernelProvider {
    func getDefaultKernel() async throws -> Kernel {
        Kernel(path: URL(fileURLWithPath: "/fake/kernel"), platform: .linuxArm)
    }
}

// MARK: - Fake ClientProcess

struct FakeClientProcess: ClientProcess {
    let id: String
    func start() async throws {}
    func resize(_: Terminal.Size) async throws {}
    func kill(_: Int32) async throws {}
    func wait() async throws -> Int32 {
        0
    }
}

// MARK: - Snapshot helpers

func makeSnapshot(
    id: String? = nil,
    config: ContainerConfiguration? = nil,
    status: RuntimeStatus = .stopped,
    labels: [String: String] = [:]
) -> ContainerSnapshot {
    var cfg = config ?? ContainerConfiguration(
        id: id ?? "test",
        image: ImageDescription(reference: "test:latest", descriptor: Descriptor(mediaType: "", digest: "sha256:fake", size: 0)),
        process: ProcessConfiguration(executable: "/bin/sleep", arguments: ["infinity"], environment: [])
    )
    for (k, v) in labels {
        cfg.labels[k] = v
    }
    return ContainerSnapshot(configuration: cfg, status: status, networks: [])
}

func makeManagedSnapshot(
    name: String,
    agent: String = "claude",
    workspace: String,
    extraWorkspaces: String = "",
    status: RuntimeStatus = .stopped
) -> ContainerSnapshot {
    let labels: [String: String] = [
        SandboxLabels.managed: "true",
        SandboxLabels.agent: agent,
        SandboxLabels.workspace: workspace,
        SandboxLabels.extraWorkspaces: extraWorkspaces,
    ]
    return makeSnapshot(id: name, status: status, labels: labels)
}
