import Foundation

/// Policy direction: allow-by-default (blocklist) or deny-by-default (allowlist).
enum PolicyDirection: String, Codable {
    /// Block all traffic except explicitly allowed hosts.
    case deny
    /// Allow all traffic except explicitly blocked hosts (+ always block private CIDRs).
    case allow
}

/// Network policy configuration for a sandbox.
/// Every sandbox runs a filtering proxy; the policy controls what traffic is permitted.
struct NetworkPolicy: Codable {
    var direction: PolicyDirection
    var allowedHosts: [String]
    var blockedHosts: [String]
    var blockedCIDRs: [String]

    /// Hosts always permitted regardless of policy direction (API endpoints).
    static let defaultAllowedHosts: [String] = [
        "*.anthropic.com",
        "platform.claude.com:443",
    ]

    /// Default blocked CIDRs — host-side private networks and localhost.
    /// Container-internal localhost (127.0.0.1 inside the VM) is unaffected.
    static let defaultBlockedCIDRs: [String] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]

    /// Allow all traffic (blocklist mode). Blocks private CIDRs.
    static let allow = NetworkPolicy(
        direction: .allow,
        allowedHosts: defaultAllowedHosts,
        blockedHosts: [],
        blockedCIDRs: defaultBlockedCIDRs
    )

    /// Deny all traffic except default allowed hosts.
    static let deny = NetworkPolicy(
        direction: .deny,
        allowedHosts: defaultAllowedHosts,
        blockedHosts: [],
        blockedCIDRs: defaultBlockedCIDRs
    )

    /// Deny-by-default with additional allowed hosts (prepends defaultAllowedHosts).
    static func deny(
        allowedHosts: [String],
        blockedHosts: [String] = [],
        blockedCIDRs: [String] = defaultBlockedCIDRs
    ) -> NetworkPolicy {
        NetworkPolicy(
            direction: .deny,
            allowedHosts: defaultAllowedHosts + allowedHosts,
            blockedHosts: blockedHosts,
            blockedCIDRs: blockedCIDRs
        )
    }
}

// MARK: - Equatable (order/case/duplicate-insensitive for host lists)

extension NetworkPolicy: Equatable {
    static func == (lhs: NetworkPolicy, rhs: NetworkPolicy) -> Bool {
        lhs.direction == rhs.direction
            && normalizedSet(lhs.allowedHosts) == normalizedSet(rhs.allowedHosts)
            && normalizedSet(lhs.blockedHosts) == normalizedSet(rhs.blockedHosts)
            && Set(lhs.blockedCIDRs) == Set(rhs.blockedCIDRs)
    }

    private static func normalizedSet(_ hosts: [String]) -> Set<String> {
        Set(hosts.map { $0.lowercased() })
    }
}

// MARK: - Label serialization

extension NetworkPolicy {
    /// Encode allowed hosts for storage in a container label.
    var allowedHostsLabel: String {
        allowedHosts.joined(separator: ",")
    }

    /// Encode blocked hosts for storage in a container label.
    var blockedHostsLabel: String {
        blockedHosts.joined(separator: ",")
    }

    /// Encode blocked CIDRs for storage in a container label.
    var blockedCIDRsLabel: String {
        blockedCIDRs.joined(separator: ",")
    }

    /// Decode a NetworkPolicy from container labels. Returns nil if the direction label is missing.
    static func fromLabels(_ labels: [String: String]) -> NetworkPolicy? {
        guard let dirRaw = labels[SandboxLabels.direction],
              let direction = PolicyDirection(rawValue: dirRaw)
        else {
            return nil
        }
        let allowedHosts = (labels[SandboxLabels.allowedHosts] ?? "")
            .split(separator: ",").map(String.init).filter { !$0.isEmpty }
        let blockedHosts = (labels[SandboxLabels.blockedHosts] ?? "")
            .split(separator: ",").map(String.init).filter { !$0.isEmpty }
        // Absent label → use defaults; present-but-empty → intentionally empty.
        let blockedCIDRs: [String]
        if let cidrsRaw = labels[SandboxLabels.blockedCIDRs] {
            blockedCIDRs = cidrsRaw.isEmpty ? [] : cidrsRaw.split(separator: ",").map(String.init)
        } else {
            blockedCIDRs = defaultBlockedCIDRs
        }
        return NetworkPolicy(
            direction: direction,
            allowedHosts: allowedHosts,
            blockedHosts: blockedHosts,
            blockedCIDRs: blockedCIDRs
        )
    }
}
