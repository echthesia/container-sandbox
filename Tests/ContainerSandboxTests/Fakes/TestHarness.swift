import Foundation

@testable import sandbox

/// Uses a real temp directory as the workspace so fileExists checks pass.
let testWorkspace = FileManager.default.temporaryDirectory.appendingPathComponent("sandbox-test-workspace").path

/// Fake libexec directory with proxy-bridge + sandbox-init placeholders so preflight checks pass.
let testLibexecPath: String = {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent("sandbox-test-libexec").path
    try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: path + "/proxy-bridge", contents: nil)
    FileManager.default.createFile(atPath: path + "/sandbox-init", contents: nil)
    return path
}()

struct TestHarness {
    let manager: SandboxManager
    let containers: FakeContainerOperations
    let images: FakeImageOperations
    let sessions: FakeSessionStorage
    let proxyLauncher: FakeProxyLauncher
    let proxyStorage: FakeProxyStateStorage

    init(
        containers: FakeContainerOperations = FakeContainerOperations(),
        images: FakeImageOperations = FakeImageOperations(),
        sessions: FakeSessionStorage = FakeSessionStorage(),
        proxyLauncher: FakeProxyLauncher = FakeProxyLauncher(),
        proxyStorage: FakeProxyStateStorage = FakeProxyStateStorage()
    ) {
        // Pre-stamp the built-in template images so tests skip the build path
        // unless they explicitly remove an entry to exercise it.
        images.existingImages = Set(
            AgentRegistry.availableAgents.compactMap { AgentRegistry.resolve($0)?.defaultImage })

        let sessionTracker = SessionTracker(storage: sessions, pidIsAlive: { _ in false })
        let proxyManager = ProxyManager(launcher: proxyLauncher, stateStorage: proxyStorage)
        manager = SandboxManager(
            containers: containers,
            images: images,
            kernels: FakeKernelProvider(),
            sessions: sessionTracker,
            proxy: proxyManager,
            libexecPath: testLibexecPath
        )
        self.containers = containers
        self.images = images
        self.sessions = sessions
        self.proxyLauncher = proxyLauncher
        self.proxyStorage = proxyStorage
    }
}
