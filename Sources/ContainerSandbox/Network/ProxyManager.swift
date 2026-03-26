import Foundation

/// Manages proxy server lifecycle for filtered sandboxes.
/// Each sandbox gets its own proxy process listening on a Unix domain socket.
enum ProxyManager {
    private static let stateDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/state/container-sandbox/proxy")

    /// Port the proxy bridge listens on inside the VM.
    /// Must match `listenAddr` in init-image/cmd/proxy-bridge/main.go.
    static let proxyPort = 3128

    /// Environment variables that direct container traffic through the proxy.
    /// Only HTTPS_PROXY is set — the proxy handles CONNECT (HTTPS tunneling) and
    /// rejects plain HTTP. Both uppercase and lowercase variants are set for
    /// compatibility (Go, wget, Python urllib check lowercase).
    static var proxyEnvironment: [(key: String, value: String)] {
        let url = "http://127.0.0.1:\(proxyPort)"
        return [
            ("HTTPS_PROXY", url),
            ("https_proxy", url),
            ("NO_PROXY", "localhost,127.0.0.1"),
            ("no_proxy", "localhost,127.0.0.1"),
        ]
    }

    /// State file tracking a running proxy.
    struct ProxyState: Codable {
        let pid: Int32
        let socketPath: String
        let sandboxName: String
    }

    /// Compute a short socket path that fits within the 104-byte UDS limit.
    static func socketPath(for sandboxName: String) -> String {
        // Use first 12 chars of SHA256 hash to keep path short.
        let hash = SandboxNaming.shortHash(sandboxName)
        return "/tmp/cs-proxy-\(hash).sock"
    }

    private static func stateFilePath(for sandboxName: String) -> URL {
        stateDir.appendingPathComponent("\(sandboxName).json")
    }

    /// Start the proxy if not already running. Returns the socket path.
    @discardableResult
    static func startIfNeeded(name: String, policy: NetworkPolicy) async throws -> String {
        let socket = socketPath(for: name)

        // Check if already running.
        if let state = try? loadState(for: name) {
            if isProcessAlive(pid: state.pid) && FileManager.default.fileExists(atPath: state.socketPath) {
                return state.socketPath
            }
            // Stale state — clean up.
            try? FileManager.default.removeItem(atPath: state.socketPath)
        }

        // Write policy config for the proxy process.
        try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
        let configPath = stateDir.appendingPathComponent("\(name)-config.json")
        let configData = try JSONEncoder().encode(policy)
        try configData.write(to: configPath)

        // Find our own executable path to launch the hidden _proxy subcommand.
        let execPath = CommandLine.arguments[0]

        let process = Process()
        process.executableURL = URL(fileURLWithPath: execPath)
        process.arguments = ["_proxy", "--socket", socket, "--config", configPath.path]
        process.standardOutput = FileHandle.nullDevice
        // Log proxy stderr for diagnostics (bind failures, policy errors, etc.)
        let logPath = stateDir.appendingPathComponent("\(name)-proxy.log")
        FileManager.default.createFile(atPath: logPath.path, contents: nil)
        process.standardError = FileHandle(forWritingAtPath: logPath.path) ?? FileHandle.nullDevice

        // Detach so the proxy outlives this process.
        process.qualityOfService = .utility
        try process.run()

        let state = ProxyState(pid: process.processIdentifier, socketPath: socket, sandboxName: name)
        try saveState(state, for: name)

        // Wait briefly for the socket to appear.
        for _ in 0 ..< 20 {
            if FileManager.default.fileExists(atPath: socket) { return socket }
            try await Task.sleep(for: .milliseconds(50))
        }

        // If the socket never appeared, the proxy failed to start.
        let logHint = FileManager.default.fileExists(atPath: logPath.path)
            ? " (see \(logPath.path))" : ""
        throw SandboxError.proxyStartFailed("proxy socket not created after 1s\(logHint)")
    }

    /// Stop the proxy for a sandbox.
    static func stop(name: String) {
        guard let state = try? loadState(for: name) else { return }

        if isProcessAlive(pid: state.pid) {
            kill(state.pid, SIGTERM)
        }

        try? FileManager.default.removeItem(atPath: state.socketPath)
        try? FileManager.default.removeItem(at: stateFilePath(for: name))
        let configPath = stateDir.appendingPathComponent("\(name)-config.json")
        try? FileManager.default.removeItem(at: configPath)
        let logPath = stateDir.appendingPathComponent("\(name)-proxy.log")
        try? FileManager.default.removeItem(at: logPath)
    }

    // MARK: - Private

    private static func loadState(for name: String) throws -> ProxyState? {
        let path = stateFilePath(for: name)
        guard FileManager.default.fileExists(atPath: path.path) else { return nil }
        let data = try Data(contentsOf: path)
        return try JSONDecoder().decode(ProxyState.self, from: data)
    }

    private static func saveState(_ state: ProxyState, for name: String) throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateFilePath(for: name))
    }

    private static func isProcessAlive(pid: Int32) -> Bool {
        kill(pid, 0) == 0
    }
}
