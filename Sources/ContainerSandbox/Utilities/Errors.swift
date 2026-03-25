import Foundation

enum SandboxError: LocalizedError {
    case unknownAgent(String)
    case sandboxNotFound(String)
    case workspaceNotFound(String)
    case imageBuildFailed(String)

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
        }
    }
}
