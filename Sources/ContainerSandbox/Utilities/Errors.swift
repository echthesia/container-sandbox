import Foundation

enum SandboxError: LocalizedError {
    case unknownAgent(String)
    case sandboxNotFound(String)
    case workspaceNotFound(String)
    case imageBuildFailed(String)
    case proxyStartFailed(String)
    case initImageMissing
    case networkPolicyMismatch(name: String, existing: NetworkPolicy, requested: NetworkPolicy)
    case extraWorkspaceMismatch(name: String)
    case workspaceMismatch(name: String, existing: String, requested: String)
    case agentMismatch(name: String, existing: String, requested: String)
    case notManagedSandbox(String)
    case outdatedSandbox(String)

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
        case .initImageMissing:
            "Custom init image 'container-sandbox-init:latest' not found. Run 'make init-image' to build it."
        case let .networkPolicyMismatch(name, existing, requested):
            {
                var diffs: [String] = []
                if existing.direction != requested.direction {
                    diffs.append("direction: \(existing.direction.rawValue) vs \(requested.direction.rawValue)")
                }
                if existing.allowedHosts != requested.allowedHosts {
                    diffs.append("allowed hosts differ")
                }
                if existing.blockedHosts != requested.blockedHosts {
                    diffs.append("blocked hosts differ")
                }
                if existing.blockedCIDRs != requested.blockedCIDRs {
                    diffs.append("blocked CIDRs differ")
                }
                let detail = diffs.isEmpty ? "policies differ" : diffs.joined(separator: ", ")
                return "Sandbox '\(name)' has a different network policy (\(detail)). Run 'sandbox rm \(name)' to recreate."
            }()
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
        }
    }
}
