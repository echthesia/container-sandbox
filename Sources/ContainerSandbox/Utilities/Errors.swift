import Foundation

enum SandboxError: LocalizedError {
    case systemNotStarted
    case unknownAgent(String)
    case sandboxNotFound(String)
    case sandboxAlreadyExists(String)
    case workspaceNotFound(String)
    case imageBuildFailed(String)
    case containerOperationFailed(String)

    var errorDescription: String? {
        switch self {
        case .systemNotStarted:
            return "Container system is not running. Run `container system start` first."
        case .unknownAgent(let name):
            return "Unknown agent '\(name)'. Available agents: \(AgentRegistry.availableAgents.joined(separator: ", "))"
        case .sandboxNotFound(let name):
            return "Sandbox '\(name)' not found."
        case .sandboxAlreadyExists(let name):
            return "Sandbox '\(name)' already exists."
        case .workspaceNotFound(let path):
            return "Workspace directory not found: \(path)"
        case .imageBuildFailed(let message):
            return "Failed to build sandbox image: \(message)"
        case .containerOperationFailed(let message):
            return message
        }
    }
}
