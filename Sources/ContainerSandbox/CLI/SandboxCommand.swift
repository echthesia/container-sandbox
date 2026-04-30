import ArgumentParser
import ContainerAPIClient
import ContainerResource
import Foundation

@main
struct SandboxCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sandbox",
        abstract: "Sandbox environments for AI coding agents",
        version: containerSandboxVersion,
        subcommands: [
            RunCommand.self,
            CreateCommand.self,
            ExecCommand.self,
            ListCommand.self,
            StopCommand.self,
            RemoveCommand.self,
            SaveCommand.self,
            NetworkCommand.self,
            ProxyCommand.self,
        ],
        defaultSubcommand: RunCommand.self
    )

    /// handleProcess uses a task group with a signal-handler task that doesn't
    /// respond to cancellation. Force-exit on errors to match the native CLI.
    static func main() async {
        do {
            var command = try parseAsRoot()
            if var asyncCommand = command as? AsyncParsableCommand {
                try await asyncCommand.run()
            } else {
                try command.run()
            }
        } catch {
            if let exitError = error as? ExitCode {
                Darwin.exit(exitError.rawValue)
            }
            Self.exit(withError: error)
        }
    }
}

// MARK: - Commands

struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Run an agent in a sandbox"
    )

    @Option(name: [.short, .long], help: "Override sandbox name")
    var name: String?

    @Option(name: [.short, .long], help: "Set environment variables (KEY=VALUE)")
    var env: [String] = []

    @Argument(help: "Agent name (\(AgentRegistry.availableAgents.joined(separator: ", "))) or existing sandbox name")
    var agent: String

    @Argument(help: "Workspace directory (default: current directory)")
    var workspace: String = "."

    @Argument(parsing: .captureForPassthrough, help: "Extra workspaces (append :ro for read-only) and agent arguments (after --)")
    var extra: [String] = []

    func run() async throws {
        var extraWorkspaces: [String] = []
        var agentArgs: [String] = []
        var seenSeparator = false
        for arg in extra {
            if arg == "--" {
                seenSeparator = true
            } else if seenSeparator {
                agentArgs.append(arg)
            } else {
                extraWorkspaces.append(arg)
            }
        }

        try await runSandbox(
            agent: agent, workspace: workspace,
            extraWorkspaces: extraWorkspaces, agentArgs: agentArgs,
            env: env, nameOverride: name
        )
    }
}

/// Resolve the image user from container labels.
/// Returns nil if no image user was stored (defaults to init process user).
private func imageUserFromLabels(_ labels: [String: String]) -> ProcessConfiguration.User? {
    guard let raw = labels[SandboxLabels.imageUser], !raw.isEmpty else { return nil }
    return .raw(userString: raw)
}

func runSandbox(
    agent: String, workspace: String,
    extraWorkspaces: [String] = [], agentArgs: [String] = [],
    env: [String] = [], nameOverride: String? = nil,
    manager: SandboxManager = SandboxManager()
) async throws {
    guard let template = AgentRegistry.resolve(agent) else {
        // Treat as existing sandbox name
        guard let snapshot = try await manager.getSandbox(name: agent) else {
            throw SandboxError.sandboxNotFound(agent)
        }
        try await manager.bootstrapIfNeeded(name: agent, snapshot: snapshot)
        let initConfig = snapshot.configuration.initProcess
        let labels = snapshot.configuration.labels
        let workDir = labels[SandboxLabels.workspace] ?? initConfig.workingDirectory

        // Recover the original agent template so we relaunch its entrypoint,
        // not a bare shell. Falls back to /bin/bash for unknown agents.
        let extraEnv = Dictionary(
            env.compactMap { parseEnvEntry($0) },
            uniquingKeysWith: { _, last in last }
        )
        let imageUser = imageUserFromLabels(labels)
        let config: ProcessConfiguration
        if let agentName = labels[SandboxLabels.agent],
            let savedTemplate = AgentRegistry.resolve(agentName)
        {
            config = savedTemplate.processConfiguration(
                baseConfig: initConfig,
                workingDirectory: workDir,
                extraArgs: agentArgs,
                extraEnv: extraEnv,
                userOverride: imageUser
            )
        } else {
            config = ProcessConfiguration(
                executable: "/bin/bash",
                arguments: [],
                environment: SandboxManager.execEnvironment(
                    base: initConfig.environment,
                    extras: env,
                    tty: true
                ),
                workingDirectory: workDir,
                terminal: true,
                user: imageUser ?? initConfig.user
            )
        }
        let exitCode = try await manager.runTracked(name: agent, configuration: config)
        throw ExitCode(exitCode)
    }

    let (sandboxName, snapshot) = try await manager.ensureSandboxExists(
        template: template,
        workspace: workspace,
        extraWorkspaces: extraWorkspaces,
        nameOverride: nameOverride
    )

    try await manager.bootstrapIfNeeded(name: sandboxName, snapshot: snapshot)

    let extraEnv = Dictionary(
        env.compactMap { parseEnvEntry($0) },
        uniquingKeysWith: { _, last in last }
    )
    let processConfig = template.processConfiguration(
        baseConfig: snapshot.configuration.initProcess,
        workingDirectory: SandboxManager.resolveWorkspacePath(workspace),
        extraArgs: agentArgs,
        extraEnv: extraEnv,
        userOverride: imageUserFromLabels(snapshot.configuration.labels)
    )

    let exitCode = try await manager.runTracked(name: sandboxName, configuration: processConfig)
    throw ExitCode(exitCode)
}

struct CreateCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "create",
        abstract: "Create a sandbox without starting it"
    )

    @Option(name: [.short, .long], help: "Override sandbox name")
    var name: String?

    @Argument(help: "Agent name (\(AgentRegistry.availableAgents.joined(separator: ", ")))")
    var agent: String

    @Argument(help: "Workspace directory")
    var workspace: String = "."

    func run() async throws {
        try await createSandbox(agent: agent, workspace: workspace, nameOverride: name)
    }
}

func createSandbox(
    agent: String, workspace: String, nameOverride: String? = nil,
    manager: SandboxManager = SandboxManager()
) async throws {
    guard let template = AgentRegistry.resolve(agent) else {
        throw SandboxError.unknownAgent(agent)
    }

    let (sandboxName, _) = try await manager.ensureSandboxExists(
        template: template,
        workspace: workspace,
        nameOverride: nameOverride
    )
    print(sandboxName)
}

struct ExecCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "exec",
        abstract: "Execute a command inside a sandbox"
    )

    @Option(name: [.short, .long], help: "Set environment variables (KEY=VALUE)")
    var env: [String] = []

    @Option(name: [.short, .long], help: "Working directory inside the sandbox")
    var workdir: String?

    @Flag(name: [.short, .long], help: "Allocate a TTY")
    var tty: Bool = false

    @Argument(help: "Sandbox name")
    var sandboxName: String

    @Argument(parsing: .captureForPassthrough, help: "Command and arguments")
    var command: [String] = []

    func run() async throws {
        try await execInSandbox(
            name: sandboxName, command: command,
            env: env, workDir: workdir, tty: tty
        )
    }
}

func execInSandbox(
    name: String, command: [String],
    env: [String] = [], workDir: String? = nil, tty: Bool = false,
    manager: SandboxManager = SandboxManager()
) async throws {
    guard let executable = command.first else {
        throw ValidationError("No command specified.")
    }

    guard let snapshot = try await manager.getSandbox(name: name) else {
        throw SandboxError.sandboxNotFound(name)
    }

    try await manager.bootstrapIfNeeded(name: name, snapshot: snapshot)

    let initConfig = snapshot.configuration.initProcess
    let labels = snapshot.configuration.labels
    let config = ProcessConfiguration(
        executable: executable,
        arguments: Array(command.dropFirst()),
        environment: SandboxManager.execEnvironment(
            base: initConfig.environment,
            extras: env,
            tty: tty
        ),
        workingDirectory: workDir ?? labels[SandboxLabels.workspace] ?? initConfig.workingDirectory,
        terminal: tty,
        user: imageUserFromLabels(labels) ?? initConfig.user
    )

    let exitCode = try await manager.runTracked(name: name, configuration: config)
    throw ExitCode(exitCode)
}

struct ListCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "List sandboxes",
        aliases: ["list"]
    )

    @Flag(name: [.short, .long], help: "Only show sandbox names")
    var quiet: Bool = false

    func run() async throws {
        try await listSandboxes(quiet: quiet)
    }
}

func listSandboxes(
    quiet: Bool = false,
    manager: SandboxManager = SandboxManager()
) async throws {
    let sandboxes = try await manager.listSandboxes()

    if sandboxes.isEmpty {
        if !quiet { print("No sandboxes found.") }
        return
    }

    if quiet {
        for s in sandboxes {
            print(s.id)
        }
    } else {
        func pad(_ str: String, _ width: Int) -> String {
            str.padding(toLength: width, withPad: " ", startingAt: 0)
        }
        print("\(pad("NAME", 40)) \(pad("AGENT", 10)) \(pad("STATUS", 10)) \(pad("POLICY", 10)) WORKSPACE")
        for s in sandboxes {
            let agent = s.configuration.labels[SandboxLabels.agent] ?? "?"
            let workspace = s.configuration.labels[SandboxLabels.workspace] ?? "?"
            let direction = (try? manager.getPolicy(for: s.id))?.direction.rawValue ?? "?"
            print("\(pad(s.id, 40)) \(pad(agent, 10)) \(pad(s.status.rawValue, 10)) \(pad(direction, 10)) \(workspace)")
        }
    }
}

struct StopCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "stop",
        abstract: "Stop one or more sandboxes"
    )

    @Argument(help: "Sandbox name(s)")
    var names: [String]

    func run() async throws {
        try await stopSandboxes(names: names)
    }
}

func stopSandboxes(
    names: [String],
    manager: SandboxManager = SandboxManager()
) async throws {
    for name in names {
        if try await manager.stopSandbox(name: name) {
            print("Stopped \(name)")
        } else {
            print("Sandbox '\(name)' not found.")
        }
    }
}

struct RemoveCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rm",
        abstract: "Remove one or more sandboxes",
        aliases: ["remove"]
    )

    @Argument(help: "Sandbox name(s)")
    var names: [String]

    func run() async throws {
        try await removeSandboxes(names: names)
    }
}

func removeSandboxes(
    names: [String],
    manager: SandboxManager = SandboxManager()
) async throws {
    for name in names {
        if try await manager.deleteSandbox(name: name) {
            print("Removed \(name)")
        } else {
            print("Sandbox '\(name)' not found.")
        }
    }
}

struct SaveCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "save",
        abstract: "Save a snapshot of a sandbox as an image"
    )

    @Argument(help: "Sandbox name")
    var sandboxName: String

    @Argument(help: "Output archive path")
    var output: String

    func run() async throws {
        try await saveSandbox(name: sandboxName, outputPath: output)
    }
}

func saveSandbox(
    name: String, outputPath: String,
    manager: SandboxManager = SandboxManager()
) async throws {
    try await manager.exportSandbox(name: name, to: outputPath)
    print("Saved \(name) to \(outputPath)")
}

// MARK: - Network management

struct NetworkCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "network",
        abstract: "Manage sandbox networking",
        subcommands: [
            NetworkProxyCommand.self,
            NetworkLogCommand.self,
        ]
    )
}

extension PolicyDirection: ExpressibleByArgument {}

struct NetworkProxyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "proxy",
        abstract: "Manage proxy configuration for a sandbox"
    )

    @Argument(help: "Sandbox name")
    var sandboxName: String

    @Option(name: .long, help: "Set the default policy")
    var policy: PolicyDirection?

    @Option(name: .long, help: "Permit access to a domain or IP")
    var allowHost: [String] = []

    @Option(name: .long, help: "Block access to a domain or IP")
    var blockHost: [String] = []

    func run() async throws {
        try await configureNetworkProxy(
            sandboxName: sandboxName, policy: policy,
            allowHost: allowHost, blockHost: blockHost
        )
    }
}

func configureNetworkProxy(
    sandboxName: String, policy: PolicyDirection? = nil,
    allowHost: [String] = [], blockHost: [String] = [],
    manager: SandboxManager = SandboxManager()
) async throws {
    // Validate sandbox exists and is managed.
    guard let snapshot = try await manager.getSandbox(name: sandboxName) else {
        throw SandboxError.sandboxNotFound(sandboxName)
    }
    guard snapshot.configuration.labels[SandboxLabels.managed] == "true" else {
        throw SandboxError.notManagedSandbox(sandboxName)
    }

    let hasOverrides = policy != nil || !allowHost.isEmpty || !blockHost.isEmpty

    if hasOverrides {
        // Mutate: load current policy, apply overrides, persist.
        let base =
            (try? manager.proxy.stateStorage.loadPolicy(for: sandboxName))
            ?? AgentRegistry.resolve(
                snapshot.configuration.labels[SandboxLabels.agent] ?? ""
            )?.defaultNetworkPolicy
            ?? .allow

        var updated = base
        if let policy {
            updated.direction = policy
        }
        if !allowHost.isEmpty {
            // Remove from block list to avoid the host appearing on both sides
            // (blocked always wins in DomainFilter, so a dual-listed host would
            // be silently unreachable despite appearing in the allow list).
            let allowSet = Set(allowHost.map { $0.lowercased() })
            updated.blockedHosts.removeAll { allowSet.contains($0.lowercased()) }
            updated.allowedHosts.append(contentsOf: allowHost)
        }
        if !blockHost.isEmpty {
            let blockSet = Set(blockHost.map { $0.lowercased() })
            updated.allowedHosts.removeAll { blockSet.contains($0.lowercased()) }
            updated.blockedHosts.append(contentsOf: blockHost)
        }

        // Start or restart the proxy with the updated policy.
        // startIfNeeded compares the on-disk policy with the requested one
        // and restarts when they differ, so we must NOT write first.
        if snapshot.status == .running {
            try await manager.proxy.startIfNeeded(name: sandboxName, policy: updated)
        } else {
            // Sandbox isn't running — just persist the policy for the next start.
            try manager.proxy.stateStorage.ensureStateDirectory(for: sandboxName)
            _ = try manager.proxy.stateStorage.writePolicy(updated, for: sandboxName)
        }
    } else {
        // Display current policy.
        guard let current = try manager.proxy.stateStorage.loadPolicy(for: sandboxName) else {
            print("No network policy configured for '\(sandboxName)'.")
            return
        }
        print("Policy: \(current.direction.rawValue)")
        if !current.allowedHosts.isEmpty {
            print("Allowed hosts:")
            for host in current.allowedHosts {
                print("  \(host)")
            }
        }
        if !current.blockedHosts.isEmpty {
            print("Blocked hosts:")
            for host in current.blockedHosts {
                print("  \(host)")
            }
        }
        if !current.blockedCIDRs.isEmpty {
            print("Blocked CIDRs:")
            for cidr in current.blockedCIDRs {
                print("  \(cidr)")
            }
        }
    }
}

struct NetworkLogCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "log",
        abstract: "Show network logs"
    )

    @Argument(help: "Sandbox name")
    var sandboxName: String

    func run() async throws {
        try await showNetworkLog(sandboxName: sandboxName)
    }
}

func showNetworkLog(
    sandboxName: String,
    manager: SandboxManager = SandboxManager()
) async throws {
    guard let snapshot = try await manager.getSandbox(name: sandboxName) else {
        throw SandboxError.sandboxNotFound(sandboxName)
    }
    guard snapshot.configuration.labels[SandboxLabels.managed] == "true" else {
        throw SandboxError.notManagedSandbox(sandboxName)
    }

    let logPath = manager.proxy.stateStorage.logPath(for: sandboxName)
    guard FileManager.default.fileExists(atPath: logPath.path) else {
        print("No proxy logs found for '\(sandboxName)'.")
        return
    }
    let contents = try String(contentsOf: logPath, encoding: .utf8)
    print(contents, terminator: "")
}

/// Hidden subcommand used by ProxyManager to run the proxy server.
struct ProxyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "_proxy",
        abstract: "",
        shouldDisplay: false
    )

    @Option(name: .long, help: "Unix domain socket path")
    var socket: String

    @Option(name: .long, help: "Path to JSON policy config file")
    var config: String

    func run() async throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: config))
        let policy = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        let filter = DomainFilter(policy: policy)
        let server = ProxyServer(socketPath: socket, filter: filter)
        try await server.run()
    }
}
