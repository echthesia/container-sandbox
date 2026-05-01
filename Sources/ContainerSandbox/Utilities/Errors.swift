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
    case networkIsolationViolated(name: String, details: String)

    var errorDescription: String? {
        switch self {
        case .unknownAgent(let name):
            "Unknown agent '\(name)'. Available agents: \(AgentRegistry.availableAgents.joined(separator: ", "))"
        case .sandboxNotFound(let name):
            "Sandbox '\(name)' not found."
        case .workspaceNotFound(let path):
            "Workspace directory not found: \(path)"
        case .imageBuildFailed(let message):
            "Failed to build sandbox image: \(message)"
        case .proxyStartFailed(let message):
            "Failed to start network proxy: \(message)"
        case .proxyBridgeMissing:
            "proxy-bridge binary not found. Run 'make install' to build and install it."
        case .extraWorkspaceMismatch(let name):
            "Sandbox '\(name)' has different extra workspace mounts. Run 'sandbox rm \(name)' to recreate."
        case .workspaceMismatch(let name, let existing, let requested):
            "Sandbox '\(name)' is bound to workspace '\(existing)', not '\(requested)'. Run 'sandbox rm \(name)' to recreate."
        case .agentMismatch(let name, let existing, let requested):
            "Sandbox '\(name)' uses agent '\(existing)', not '\(requested)'. Run 'sandbox rm \(name)' to recreate."
        case .notManagedSandbox(let name):
            "'\(name)' is not a sandbox managed by this plugin."
        case .outdatedSandbox(let name):
            "Sandbox '\(name)' was created with an older version. Run 'sandbox rm \(name)' and recreate it."
        case .invalidName(let name):
            "Invalid sandbox name '\(name)'. Names must not be empty or contain '/' or '..'."
        case .nameTooLong(let name, let limit):
            "Sandbox name '\(name)' is \(name.utf8.count) bytes; must be at most \(limit) (constrained by the in-guest socket relay path)."
        case .reservedName(let name):
            "'\(name)' is a built-in agent template name and cannot be used as a sandbox name."
        case .networkIsolationViolated(let name, let details):
            "Sandbox '\(name)' has unexpected network attachments (\(details)). The proxy is the only sanctioned egress; refusing to use this container."
        }
    }
}
