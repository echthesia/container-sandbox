import Foundation

/// Abstracts process launching for proxy management, enabling testing without real processes.
protocol ProxyLauncher: Sendable {
    /// Launch a proxy process with given arguments. Returns the PID.
    func launch(executable: String, arguments: [String], logPath: URL) throws -> Int32
    func isProcessAlive(pid: Int32) -> Bool
    func killProcess(pid: Int32)
}

/// Abstracts state persistence and filesystem operations for proxy management.
protocol ProxyStateStorage: Sendable {
    func ensureStateDirectory(for name: String) throws
    func loadState(for name: String) throws -> ProxyState?
    func saveState(_ state: ProxyState, for name: String) throws
    /// Remove runtime state (PID, lock, log) but preserve the policy config.
    func removeRuntimeState(for name: String)
    /// Remove all state including the persistent policy config.
    func removeAll(for name: String)
    func writePolicy(_ policy: NetworkPolicy, for name: String) throws -> String
    func loadPolicy(for name: String) throws -> NetworkPolicy?
    func socketExists(path: String) -> Bool
    func removeSocket(path: String)
    func ensureSocketDir(for name: String)
    func removeSocketDir(for name: String)
    func logPath(for name: String) -> URL
    /// Acquire a per-sandbox lock. Returns a handle that releases on deinit/close.
    func acquireLock(for name: String) throws -> ProxyLockHandle
}

/// State file tracking a running proxy.
struct ProxyState: Codable {
    let pid: Int32
    let socketPath: String
    let sandboxName: String
}

/// Handle for a proxy lock. Releasing closes the lock.
final class ProxyLockHandle: Sendable {
    private let fd: Int32
    init(fd: Int32) {
        self.fd = fd
    }

    deinit {
        flock(fd, LOCK_UN)
        close(fd)
    }
}

/// Default process launcher using Foundation.Process.
struct SystemProxyLauncher: ProxyLauncher {
    func launch(executable: String, arguments: [String], logPath: URL) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        FileManager.default.createFile(atPath: logPath.path, contents: nil)
        process.standardError = FileHandle(forWritingAtPath: logPath.path) ?? FileHandle.nullDevice
        process.qualityOfService = .utility
        try process.run()
        return process.processIdentifier
    }

    func isProcessAlive(pid: Int32) -> Bool {
        kill(pid, 0) == 0
    }

    func killProcess(pid: Int32) {
        kill(pid, SIGTERM)
    }
}

/// Default filesystem-backed state storage for proxy management.
/// All per-sandbox state lives under `~/.local/state/container-sandbox/{name}/`.
struct FileProxyStateStorage: ProxyStateStorage {
    private let stateDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/state/container-sandbox")

    private func sandboxDir(for name: String) -> URL {
        stateDir.appendingPathComponent(name)
    }

    func ensureStateDirectory(for name: String) throws {
        try FileManager.default.createDirectory(at: sandboxDir(for: name), withIntermediateDirectories: true)
    }

    func loadState(for name: String) throws -> ProxyState? {
        let path = sandboxDir(for: name).appendingPathComponent("proxy.json")
        guard FileManager.default.fileExists(atPath: path.path) else { return nil }
        let data = try Data(contentsOf: path)
        return try JSONDecoder().decode(ProxyState.self, from: data)
    }

    func saveState(_ state: ProxyState, for name: String) throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: sandboxDir(for: name).appendingPathComponent("proxy.json"), options: .atomic)
    }

    func removeRuntimeState(for name: String) {
        let dir = sandboxDir(for: name)
        for file in ["proxy.json", "proxy.lock", "proxy.log"] {
            try? FileManager.default.removeItem(at: dir.appendingPathComponent(file))
        }
    }

    func removeAll(for name: String) {
        try? FileManager.default.removeItem(at: sandboxDir(for: name))
    }

    func writePolicy(_ policy: NetworkPolicy, for name: String) throws -> String {
        let configPath = sandboxDir(for: name).appendingPathComponent("policy.json")
        let data = try JSONEncoder().encode(policy)
        try data.write(to: configPath, options: .atomic)
        return configPath.path
    }

    func loadPolicy(for name: String) throws -> NetworkPolicy? {
        let configPath = sandboxDir(for: name).appendingPathComponent("policy.json")
        guard FileManager.default.fileExists(atPath: configPath.path) else { return nil }
        let data = try Data(contentsOf: configPath)
        return try JSONDecoder().decode(NetworkPolicy.self, from: data)
    }

    func socketExists(path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    func removeSocket(path: String) {
        try? FileManager.default.removeItem(atPath: path)
    }

    func ensureSocketDir(for name: String) {
        let dir = ProxyManager.socketDir(for: name)
        mkdir(dir, 0o700)
    }

    func removeSocketDir(for name: String) {
        let dir = ProxyManager.socketDir(for: name)
        try? FileManager.default.removeItem(atPath: dir)
    }

    func logPath(for name: String) -> URL {
        sandboxDir(for: name).appendingPathComponent("proxy.log")
    }

    func acquireLock(for name: String) throws -> ProxyLockHandle {
        let lockPath = sandboxDir(for: name).appendingPathComponent("proxy.lock").path
        FileManager.default.createFile(atPath: lockPath, contents: nil)
        let fd = open(lockPath, O_RDWR | O_CLOEXEC)
        guard fd >= 0 else {
            throw SandboxError.proxyStartFailed("failed to open proxy lock file")
        }
        guard flock(fd, LOCK_EX) == 0 else {
            close(fd)
            throw SandboxError.proxyStartFailed("failed to acquire proxy lock")
        }
        return ProxyLockHandle(fd: fd)
    }
}

/// Manages proxy server lifecycle for filtered sandboxes.
/// Each sandbox gets its own proxy process listening on a Unix domain socket.
struct ProxyManager {
    let launcher: any ProxyLauncher
    let stateStorage: any ProxyStateStorage

    init(
        launcher: any ProxyLauncher = SystemProxyLauncher(),
        stateStorage: any ProxyStateStorage = FileProxyStateStorage()
    ) {
        self.launcher = launcher
        self.stateStorage = stateStorage
    }

    /// Port the proxy bridge listens on inside the VM.
    /// Must match `listenAddr` in init-image/cmd/proxy-bridge/main.go.
    static let proxyPort = 3128

    /// Environment variables that direct container traffic through the proxy.
    /// The proxy handles CONNECT (HTTPS tunneling), plain HTTP forwarding,
    /// and SOCKS5 (arbitrary TCP). Both uppercase and lowercase variants are
    /// set for compatibility (Go, wget, Python urllib check lowercase).
    /// ALL_PROXY uses socks5h:// so the proxy resolves DNS, preserving
    /// domain names for filtering.
    static var proxyEnvironment: [(key: String, value: String)] {
        let httpUrl = "http://127.0.0.1:\(proxyPort)"
        let socksUrl = "socks5h://127.0.0.1:\(proxyPort)"
        return [
            ("HTTPS_PROXY", httpUrl),
            ("https_proxy", httpUrl),
            ("HTTP_PROXY", httpUrl),
            ("http_proxy", httpUrl),
            ("ALL_PROXY", socksUrl),
            ("all_proxy", socksUrl),
            ("NO_PROXY", "localhost,127.0.0.1"),
            ("no_proxy", "localhost,127.0.0.1"),
        ]
    }

    /// Compute a short socket path that fits within the 104-byte UDS limit.
    /// The socket lives inside a 0o700 directory so permissions are enforced
    /// by the directory — no TOCTOU window between bind and chmod.
    static func socketDir(for sandboxName: String) -> String {
        let hash = SandboxNaming.shortHash(sandboxName)
        return "/tmp/cs-proxy-\(hash)"
    }

    static func socketPath(for sandboxName: String) -> String {
        "\(socketDir(for: sandboxName))/proxy.sock"
    }

    /// Start the proxy if not already running. Returns the socket path.
    /// Uses a per-sandbox file lock to prevent concurrent invocations from racing.
    @discardableResult
    func startIfNeeded(name: String, policy: NetworkPolicy) async throws -> String {
        try stateStorage.ensureStateDirectory(for: name)

        let lock = try stateStorage.acquireLock(for: name)
        defer { withExtendedLifetime(lock) {} }

        let socket = Self.socketPath(for: name)

        // Check if already running.
        if let state = try? stateStorage.loadState(for: name) {
            if launcher.isProcessAlive(pid: state.pid) && stateStorage.socketExists(path: state.socketPath) {
                // If the policy hasn't changed, reuse the running proxy.
                let existingPolicy = try? stateStorage.loadPolicy(for: name)
                if existingPolicy == policy {
                    return state.socketPath
                }
                // Policy changed — kill the old proxy and start a new one.
                launcher.killProcess(pid: state.pid)
            }
            // Stale or killed — clean up.
            stateStorage.removeSocket(path: state.socketPath)
        }

        // Create a private directory for the socket (0o700 — no TOCTOU).
        stateStorage.ensureSocketDir(for: name)

        // Write policy config for the proxy process.
        let configPath = try stateStorage.writePolicy(policy, for: name)

        // Find our own executable path to launch the hidden _proxy subcommand.
        let execPath = CommandLine.arguments[0]
        let logPath = stateStorage.logPath(for: name)

        let pid = try launcher.launch(
            executable: execPath,
            arguments: ["_proxy", "--socket", socket, "--config", configPath],
            logPath: logPath
        )

        let state = ProxyState(pid: pid, socketPath: socket, sandboxName: name)
        try stateStorage.saveState(state, for: name)

        // Wait briefly for the socket to appear.
        for _ in 0 ..< 20 {
            if stateStorage.socketExists(path: socket) { return socket }
            try await Task.sleep(for: .milliseconds(50))
        }

        // If the socket never appeared, clean up the launched process and state.
        launcher.killProcess(pid: pid)
        stateStorage.removeRuntimeState(for: name)

        let logHint = stateStorage.socketExists(path: logPath.path)
            ? " (see \(logPath.path))" : ""
        throw SandboxError.proxyStartFailed("proxy socket not created after 1s\(logHint)")
    }

    /// Stop the proxy for a sandbox, preserving the persistent policy config.
    func stop(name: String) {
        if let state = try? stateStorage.loadState(for: name) {
            if launcher.isProcessAlive(pid: state.pid) {
                launcher.killProcess(pid: state.pid)
            }
            stateStorage.removeSocket(path: state.socketPath)
        }
        stateStorage.removeSocketDir(for: name)
        stateStorage.removeRuntimeState(for: name)
    }
}
