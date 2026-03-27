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
            && normalizedCIDRSet(lhs.blockedCIDRs) == normalizedCIDRSet(rhs.blockedCIDRs)
    }

    private static func normalizedSet(_ hosts: [String]) -> Set<String> {
        Set(hosts.map { $0.lowercased() })
    }

    private static func normalizedCIDRSet(_ cidrs: [String]) -> Set<String> {
        Set(cidrs.map { cidr in
            let parts = cidr.split(separator: "/", maxSplits: 1)
            guard parts.count == 2, let prefix = Int(parts[1]) else { return cidr }
            return "\(parts[0])/\(prefix)"
        })
    }
}
