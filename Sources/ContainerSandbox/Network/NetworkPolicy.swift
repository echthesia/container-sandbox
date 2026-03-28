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

// MARK: - Codable (validates CIDRs on decode)

extension NetworkPolicy {
    enum CodingKeys: String, CodingKey {
        case direction, allowedHosts, blockedHosts, blockedCIDRs
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        direction = try container.decode(PolicyDirection.self, forKey: .direction)
        allowedHosts = try container.decode([String].self, forKey: .allowedHosts)
        blockedHosts = try container.decode([String].self, forKey: .blockedHosts)
        blockedCIDRs = try container.decode([String].self, forKey: .blockedCIDRs)
        for cidr in blockedCIDRs {
            guard NormalizedCIDR(cidr) != nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .blockedCIDRs, in: container,
                    debugDescription: "Invalid CIDR '\(cidr)' in policy — fix or delete the policy file"
                )
            }
        }
    }
}

// MARK: - Equatable (order/case/duplicate-insensitive for host lists, binary for CIDRs)

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

    private static func normalizedCIDRSet(_ cidrs: [String]) -> Set<NormalizedCIDR> {
        Set(cidrs.compactMap { NormalizedCIDR($0) })
    }
}

/// Binary representation of a CIDR for case/format-insensitive comparison.
/// Uses inet_pton to parse the address into raw bytes so that "FC00::/7",
/// "fc00::/7", and "0:0:0:0:0:0:0:0/7" (if within range) all compare equal.
struct NormalizedCIDR: Hashable {
    let addressBytes: [UInt8]
    let prefixLength: Int

    init?(_ cidr: String) {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let prefix = Int(parts[1]) else { return nil }
        let addr = String(parts[0])

        // Try IPv4 first, then IPv6.
        var sa4 = in_addr()
        if inet_pton(AF_INET, addr, &sa4) == 1 {
            guard prefix >= 0, prefix <= 32 else { return nil }
            addressBytes = withUnsafeBytes(of: sa4) { Array($0) }
            prefixLength = prefix
            return
        }
        var sa6 = in6_addr()
        if inet_pton(AF_INET6, addr, &sa6) == 1 {
            guard prefix >= 0, prefix <= 128 else { return nil }
            addressBytes = withUnsafeBytes(of: sa6) { Array($0) }
            prefixLength = prefix
            return
        }
        return nil
    }
}
