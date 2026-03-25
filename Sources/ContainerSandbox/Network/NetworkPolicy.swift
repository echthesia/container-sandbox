import Foundation

/// Network mode for a sandbox.
enum NetworkMode: String, CaseIterable, Sendable, Codable {
    /// Unrestricted NAT networking (current default).
    case full
    /// No network interface at all.
    case none
    /// No network interface; traffic routed through a host-side filtering proxy via UDS.
    case filtered
}

/// Policy direction for filtered mode.
enum PolicyDirection: String, Sendable, Codable {
    /// Block all traffic except explicitly allowed hosts (default).
    case deny
    /// Allow all traffic except explicitly blocked hosts (+ always block private CIDRs).
    case allow
}

/// Network policy configuration for a sandbox.
struct NetworkPolicy: Sendable, Equatable, Codable {
    var mode: NetworkMode
    var direction: PolicyDirection
    var allowedHosts: [String]
    var blockedHosts: [String]
    var blockedCIDRs: [String]

    /// Full network access, no restrictions.
    static let full = NetworkPolicy(
        mode: .full,
        direction: .deny,
        allowedHosts: [],
        blockedHosts: [],
        blockedCIDRs: []
    )

    /// No network at all.
    static let none = NetworkPolicy(
        mode: .none,
        direction: .deny,
        allowedHosts: [],
        blockedHosts: [],
        blockedCIDRs: []
    )

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

    /// Create a filtered policy with allowed hosts and default CIDR blocks.
    static func filtered(
        allowedHosts: [String],
        direction: PolicyDirection = .deny,
        blockedHosts: [String] = [],
        blockedCIDRs: [String] = defaultBlockedCIDRs
    ) -> NetworkPolicy {
        NetworkPolicy(
            mode: .filtered,
            direction: direction,
            allowedHosts: allowedHosts,
            blockedHosts: blockedHosts,
            blockedCIDRs: blockedCIDRs
        )
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
}
