import Foundation

enum SandboxError: LocalizedError {
    case unknownAgent(String)
    case sandboxNotFound(String)
    case workspaceNotFound(String)
    case imageBuildFailed(String)

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
        }
    }
}
