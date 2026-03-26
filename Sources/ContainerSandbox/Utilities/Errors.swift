import Foundation

enum SandboxError: LocalizedError {
    case unknownAgent(String)
    case sandboxNotFound(String)
    case workspaceNotFound(String)
    case imageBuildFailed(String)
    case proxyStartFailed(String)
    case initImageMissing
    case networkPolicyMismatch(name: String, existing: String, requested: String)
    case outdatedSandbox(String)

    var errorDescription: String? {
        switch self {
        case .unknownAgent(let name):
            return "Unknown agent '\(name)'. Available agents: \(AgentRegistry.availableAgents.joined(separator: ", "))"
        case .sandboxNotFound(let name):
            return "Sandbox '\(name)' not found."
        case .workspaceNotFound(let path):
            return "Workspace directory not found: \(path)"
        case .imageBuildFailed(let message):
            return "Failed to build sandbox image: \(message)"
        case .proxyStartFailed(let message):
            return "Failed to start network proxy: \(message)"
        case .initImageMissing:
            return "Custom init image 'container-sandbox-init:latest' not found. Run 'make init-image' to build it."
        case .networkPolicyMismatch(let name, let existing, let requested):
            return "Sandbox '\(name)' exists with policy '\(existing)' but '\(requested)' was requested. Run 'sandbox rm \(name)' to recreate."
        case .outdatedSandbox(let name):
            return "Sandbox '\(name)' was created with an older version. Run 'sandbox rm \(name)' and recreate it."
        }
    }
}
