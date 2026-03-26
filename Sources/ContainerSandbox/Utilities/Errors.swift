import Foundation

enum SandboxError: LocalizedError {
    case unknownAgent(String)
    case sandboxNotFound(String)
    case workspaceNotFound(String)
    case imageBuildFailed(String)
    case proxyStartFailed(String)
    case initImageMissing
    case networkPolicyMismatch(name: String, existing: NetworkPolicy, requested: NetworkPolicy)
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
        case .outdatedSandbox(let name):
            return "Sandbox '\(name)' was created with an older version. Run 'sandbox rm \(name)' and recreate it."
        }
    }
}
