import Foundation

enum SandboxError: LocalizedError {
    case unknownAgent(String)
    case sandboxNotFound(String)
    case workspaceNotFound(String)
    case imageBuildFailed(String)
    case proxyStartFailed(String)
    case proxyBridgeMissing
    case extraWorkspaceMismatch(name: String)
    case workspaceMismatch(name: String, existing: String, requested: String)
    case agentMismatch(name: String, existing: String, requested: String)
    case notManagedSandbox(String)
    case outdatedSandbox(String)
    case invalidName(String)
    case nameTooLong(name: String, limit: Int)
    case reservedName(String)

    var errorDescription: String? {
        switch self {
        case let .unknownAgent(name):
            "Unknown agent '\(name)'. Available agents: \(AgentRegistry.availableAgents.joined(separator: ", "))"
        case let .sandboxNotFound(name):
            "Sandbox '\(name)' not found."
        case let .workspaceNotFound(path):
            "Workspace directory not found: \(path)"
        case let .imageBuildFailed(message):
            "Failed to build sandbox image: \(message)"
        case let .proxyStartFailed(message):
            "Failed to start network proxy: \(message)"
        case .proxyBridgeMissing:
            "proxy-bridge binary not found. Run 'make install' to build and install it."
        case let .extraWorkspaceMismatch(name):
            "Sandbox '\(name)' has different extra workspace mounts. Run 'sandbox rm \(name)' to recreate."
        case let .workspaceMismatch(name, existing, requested):
            "Sandbox '\(name)' is bound to workspace '\(existing)', not '\(requested)'. Run 'sandbox rm \(name)' to recreate."
        case let .agentMismatch(name, existing, requested):
            "Sandbox '\(name)' uses agent '\(existing)', not '\(requested)'. Run 'sandbox rm \(name)' to recreate."
        case let .notManagedSandbox(name):
            "'\(name)' is not a sandbox managed by this plugin."
        case let .outdatedSandbox(name):
            "Sandbox '\(name)' was created with an older version. Run 'sandbox rm \(name)' and recreate it."
        case let .invalidName(name):
            "Invalid sandbox name '\(name)'. Names must not be empty or contain '/' or '..'."
        case let .nameTooLong(name, limit):
            "Sandbox name '\(name)' is \(name.utf8.count) bytes; must be at most \(limit) (constrained by the in-guest socket relay path)."
        case let .reservedName(name):
            "'\(name)' is a built-in agent template name and cannot be used as a sandbox name."
        }
    }
}
