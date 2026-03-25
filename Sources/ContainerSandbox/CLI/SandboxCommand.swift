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
        ],
        defaultSubcommand: RunCommand.self
    )

    // handleProcess uses a task group with a signal-handler task that doesn't
    // respond to cancellation. When errors occur, the group hangs waiting for it.
    // Force-exit on errors to match the native CLI's behavior.
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

struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Run an agent in a sandbox"
    )

    @Argument(help: "Agent name (e.g., claude, shell) or existing sandbox name")
    var agent: String

    @Argument(help: "Workspace directory (default: current directory)")
    var workspace: String = "."

    @Argument(parsing: .captureForPassthrough, help: "Extra workspaces (append :ro for read-only) and agent arguments (after --)")
    var extra: [String] = []

    @Option(name: [.short, .long], help: "Override sandbox name")
    var name: String?

    @Option(name: [.short, .long], help: "Set environment variables (KEY=VALUE)")
    var env: [String] = []

    func run() async throws {
        // Split extra into workspace paths and agent args (separated by --)
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

        // Resolve agent template, or treat as existing sandbox name
        guard let template = AgentRegistry.resolve(agent) else {
            // Maybe it's an existing sandbox name
            guard let snapshot = try await manager.getSandbox(name: agent) else {
                throw SandboxError.unknownAgent(agent)
            }
            // Run a shell in existing sandbox
            try await manager.bootstrapIfNeeded(name: agent)
            let initConfig = snapshot.configuration.initProcess
            let config = ProcessConfiguration(
                executable: "/bin/bash",
                arguments: [],
                environment: initConfig.environment + ["TERM=xterm-256color"],
                terminal: true,
                user: initConfig.user
            )
            let sessionId = try SessionTracker.create(for: agent)
            let exitCode: Int32
            do {
                exitCode = try await manager.runProcess(name: agent, configuration: config)
            } catch {
                let wasLast = SessionTracker.remove(sessionId: sessionId, for: agent)
                if wasLast { try? await manager.stopSandbox(name: agent) }
                throw error
            }
            let wasLast = SessionTracker.remove(sessionId: sessionId, for: agent)
            if wasLast { try? await manager.stopSandbox(name: agent) }
            throw ExitCode(exitCode)
        }

        // Resolve workspace
        let resolvedWorkspace = URL(
            fileURLWithPath: workspace,
            relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        ).standardized.path

        // Parse extra env from -e flags
        var extraEnv: [String: String] = [:]
        for e in env {
            let parts = e.split(separator: "=", maxSplits: 1)
            if parts.count == 2 {
                extraEnv[String(parts[0])] = String(parts[1])
            }
        }

        // Ensure sandbox exists
        let sandboxName = try await manager.ensureSandboxExists(
            template: template,
            workspace: workspace,
            extraWorkspaces: extraWorkspaces
        )

        // Bootstrap if needed
        try await manager.bootstrapIfNeeded(name: sandboxName)

        // Get the container snapshot to inherit user/env from init config
        guard let snapshot = try await manager.getSandbox(name: sandboxName) else {
            throw SandboxError.sandboxNotFound(sandboxName)
        }

        // Build process config for the agent
        let processConfig = template.processConfiguration(
            baseConfig: snapshot.configuration.initProcess,
            workingDirectory: resolvedWorkspace,
            extraArgs: agentArgs,
            extraEnv: extraEnv
        )

        // Track session and auto-stop when last session exits
        let sessionId = try SessionTracker.create(for: sandboxName)
        let exitCode: Int32
        do {
            exitCode = try await manager.runProcess(name: sandboxName, configuration: processConfig)
        } catch {
            let wasLast = SessionTracker.remove(sessionId: sessionId, for: sandboxName)
            if wasLast { try? await manager.stopSandbox(name: sandboxName) }
            throw error
        }
        let wasLast = SessionTracker.remove(sessionId: sessionId, for: sandboxName)
        if wasLast {
            try? await manager.stopSandbox(name: sandboxName)
        }
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

    func run() async throws {
        guard let template = AgentRegistry.resolve(agent) else {
            throw SandboxError.unknownAgent(agent)
        }

        let manager = SandboxManager()
        let name = try await manager.ensureSandboxExists(
            template: template,
            workspace: workspace
        )
        print(name)
    }
}

struct ExecCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "exec",
        abstract: "Execute a command inside a sandbox"
    )

    @Argument(help: "Sandbox name")
    var sandboxName: String

    @Argument(parsing: .captureForPassthrough, help: "Command and arguments")
    var command: [String] = []

    @Option(name: [.short, .long], help: "Set environment variables (KEY=VALUE)")
    var env: [String] = []

    @Option(name: [.short, .long], help: "Working directory inside the sandbox")
    var workdir: String?

    @Flag(name: [.short, .long], help: "Allocate a TTY")
    var tty: Bool = false

    func run() async throws {
        guard let executable = command.first else {
            throw ValidationError("No command specified.")
        }

        let manager = SandboxManager()
        guard let snapshot = try await manager.getSandbox(name: sandboxName) else {
            throw SandboxError.sandboxNotFound(sandboxName)
        }

        try await manager.bootstrapIfNeeded(name: sandboxName)

        // Inherit user and base env from the container's init process config
        let initConfig = snapshot.configuration.initProcess
        var envStrings = initConfig.environment
        envStrings.append("TERM=xterm-256color")
        for e in env {
            envStrings.append(e)
        }

        let config = ProcessConfiguration(
            executable: executable,
            arguments: Array(command.dropFirst()),
            environment: envStrings,
            workingDirectory: workdir ?? initConfig.workingDirectory,
            terminal: tty,
            user: initConfig.user
        )

        // Track session and auto-stop when last session exits
        let sessionId = try SessionTracker.create(for: sandboxName)
        let exitCode: Int32
        do {
            exitCode = try await manager.runProcess(name: sandboxName, configuration: config)
        } catch {
            let wasLast = SessionTracker.remove(sessionId: sessionId, for: sandboxName)
            if wasLast { try? await manager.stopSandbox(name: sandboxName) }
            throw error
        }
        let wasLast = SessionTracker.remove(sessionId: sessionId, for: sandboxName)
        if wasLast { try? await manager.stopSandbox(name: sandboxName) }
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
            if !quiet {
                print("No sandboxes found.")
            }
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
            print("\(pad("NAME", 40)) \(pad("AGENT", 10)) \(pad("STATUS", 10)) WORKSPACE")
            for s in sandboxes {
                let agent = s.configuration.labels["sandbox.agent"] ?? "?"
                let workspace = s.configuration.labels["sandbox.workspace"] ?? "?"
                print("\(pad(s.id, 40)) \(pad(agent, 10)) \(pad(s.status.rawValue, 10)) \(workspace)")
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
