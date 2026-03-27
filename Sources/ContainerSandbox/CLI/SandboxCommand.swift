import ArgumentParser
import ContainerAPIClient
import ContainerResource
import Foundation

@main
struct SandboxCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sandbox",
        abstract: "Sandbox environments for AI coding agents",
        subcommands: [
            RunCommand.self,
            CreateCommand.self,
            ExecCommand.self,
            ListCommand.self,
            StopCommand.self,
            RemoveCommand.self,
            SaveCommand.self,
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

// MARK: - Shared option groups

extension PolicyDirection: ExpressibleByArgument {}

struct NetworkPolicyOptions: ParsableArguments {
    @Option(name: .long, help: "Network policy: allow (default, blocklist) or deny (allowlist)")
    var policy: PolicyDirection?

    @Option(name: .long, help: "Allow a host (e.g., *.github.com)")
    var allowHost: [String] = []

    @Option(name: .long, help: "Block a host")
    var blockHost: [String] = []

    /// Resolve network policy from template defaults + CLI overrides.
    /// Changes only the direction (preserving template-specific hosts),
    /// then appends any extra allow/block hosts from the CLI.
    func resolve(template: any AgentTemplate) -> NetworkPolicy {
        var resolved = template.defaultNetworkPolicy
        if let policy {
            resolved.direction = policy
        }
        if !allowHost.isEmpty {
            resolved.allowedHosts.append(contentsOf: allowHost)
        }
        if !blockHost.isEmpty {
            resolved.blockedHosts.append(contentsOf: blockHost)
        }
        return resolved
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

    @OptionGroup var networkOptions: NetworkPolicyOptions

    @Argument(help: "Agent name (e.g., claude, shell) or existing sandbox name")
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

        let manager = SandboxManager()

        guard let template = AgentRegistry.resolve(agent) else {
            // Treat as existing sandbox name
            guard let snapshot = try await manager.getSandbox(name: agent) else {
                throw SandboxError.sandboxNotFound(agent)
            }
            try await manager.bootstrapIfNeeded(name: agent, snapshot: snapshot)
            let initConfig = snapshot.configuration.initProcess
            let config = ProcessConfiguration(
                executable: "/bin/bash",
                arguments: [],
                environment: SandboxManager.execEnvironment(
                    base: initConfig.environment,
                    extras: env
                ),
                workingDirectory: snapshot.configuration.labels[SandboxLabels.workspace] ?? initConfig.workingDirectory,
                terminal: true,
                user: initConfig.user
            )
            let exitCode = try await manager.runTracked(name: agent, configuration: config)
            throw ExitCode(exitCode)
        }

        let networkPolicy = networkOptions.resolve(template: template)

        let (sandboxName, snapshot) = try await manager.ensureSandboxExists(
            template: template,
            workspace: workspace,
            extraWorkspaces: extraWorkspaces,
            networkPolicy: networkPolicy,
            nameOverride: name
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
            extraEnv: extraEnv
        )

        let exitCode = try await manager.runTracked(name: sandboxName, configuration: processConfig)
        throw ExitCode(exitCode)
    }
}

struct CreateCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "create",
        abstract: "Create a sandbox without starting it"
    )

    @Argument(help: "Agent name (e.g., claude, shell)")
    var agent: String

    @Argument(help: "Workspace directory")
    var workspace: String = "."

    @OptionGroup var networkOptions: NetworkPolicyOptions

    func run() async throws {
        guard let template = AgentRegistry.resolve(agent) else {
            throw SandboxError.unknownAgent(agent)
        }

        let networkPolicy = networkOptions.resolve(template: template)

        let manager = SandboxManager()
        let (name, _) = try await manager.ensureSandboxExists(
            template: template,
            workspace: workspace,
            networkPolicy: networkPolicy
        )
        print(name)
    }
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
        guard let executable = command.first else {
            throw ValidationError("No command specified.")
        }

        let manager = SandboxManager()
        guard let snapshot = try await manager.getSandbox(name: sandboxName) else {
            throw SandboxError.sandboxNotFound(sandboxName)
        }

        try await manager.bootstrapIfNeeded(name: sandboxName, snapshot: snapshot)

        let initConfig = snapshot.configuration.initProcess
        let config = ProcessConfiguration(
            executable: executable,
            arguments: Array(command.dropFirst()),
            environment: SandboxManager.execEnvironment(
                base: initConfig.environment,
                extras: env
            ),
            workingDirectory: workdir ?? snapshot.configuration.labels[SandboxLabels.workspace] ?? initConfig.workingDirectory,
            terminal: tty,
            user: initConfig.user
        )

        let exitCode = try await manager.runTracked(name: sandboxName, configuration: config)
        throw ExitCode(exitCode)
    }
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
        let manager = SandboxManager()
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
                let direction = s.configuration.labels[SandboxLabels.direction] ?? "?"
                print("\(pad(s.id, 40)) \(pad(agent, 10)) \(pad(s.status.rawValue, 10)) \(pad(direction, 10)) \(workspace)")
            }
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
        let manager = SandboxManager()
        for name in names {
            try await manager.stopSandbox(name: name)
            print("Stopped \(name)")
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
        let manager = SandboxManager()
        for name in names {
            try await manager.deleteSandbox(name: name)
            print("Removed \(name)")
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
        let manager = SandboxManager()
        try await manager.exportSandbox(name: sandboxName, to: output)
        print("Saved \(sandboxName) to \(output)")
    }
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
