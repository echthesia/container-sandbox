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
    var blockedCIDRs: [NormalizedCIDR]

    /// Hosts always permitted regardless of policy direction (API endpoints).
    static let defaultAllowedHosts: [String] = [
        "*.anthropic.com",
        "platform.claude.com:443",
    ]

    /// Default blocked CIDRs — host-side private networks and localhost.
    /// Container-internal localhost (127.0.0.1 inside the VM) is unaffected.
    /// Force-unwrapped because these literals are compile-time constants; a bad
    /// entry is a programmer error that should fail loudly at startup.
    static let defaultBlockedCIDRs: [NormalizedCIDR] = [
        NormalizedCIDR("10.0.0.0/8")!,
        NormalizedCIDR("172.16.0.0/12")!,
        NormalizedCIDR("192.168.0.0/16")!,
        NormalizedCIDR("127.0.0.0/8")!,
        NormalizedCIDR("169.254.0.0/16")!,
        NormalizedCIDR("::1/128")!,
        NormalizedCIDR("fc00::/7")!,
        NormalizedCIDR("fe80::/10")!,
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
        blockedCIDRs: [NormalizedCIDR] = defaultBlockedCIDRs
    ) -> NetworkPolicy {
        NetworkPolicy(
            direction: .deny,
            allowedHosts: defaultAllowedHosts + allowedHosts,
            blockedHosts: blockedHosts,
            blockedCIDRs: blockedCIDRs
        )
    }
}

// MARK: - Equatable (order/case/duplicate-insensitive for host lists, binary for CIDRs)

extension NetworkPolicy: Equatable {
    static func == (lhs: NetworkPolicy, rhs: NetworkPolicy) -> Bool {
        lhs.direction == rhs.direction
            && normalizedSet(lhs.allowedHosts) == normalizedSet(rhs.allowedHosts)
            && normalizedSet(lhs.blockedHosts) == normalizedSet(rhs.blockedHosts)
            && Set(lhs.blockedCIDRs) == Set(rhs.blockedCIDRs)
    }

    /// Normalize hosts the same way DomainFilter.parseHosts does: trim
    /// whitespace, lowercase, strip trailing dots. Two policies that produce
    /// identical filter behavior must compare equal.
    private static func normalizedSet(_ hosts: [String]) -> Set<String> {
        Set(hosts.map { raw in
            var h = raw.trimmingCharacters(in: .whitespaces).lowercased()
            while h.hasSuffix(".") {
                h = String(h.dropLast())
            }
            return h
        })
    }
}

/// Binary representation of a CIDR for case/format-insensitive comparison.
/// Uses inet_pton to parse the address into raw bytes so that "FC00::/7",
/// "fc00::/7", and "0:0:0:0:0:0:0:0/7" (if within range) all compare equal.
/// The address is stored post-masked — host bits beyond the prefix length are
/// zeroed — so 10.0.0.1/8 is indistinguishable from 10.0.0.0/8.
struct NormalizedCIDR: Hashable, Codable, CustomStringConvertible {
    let addressBytes: [UInt8] // 4 bytes for IPv4, 16 for IPv6
    let prefixLength: Int

    init?(_ cidr: String) {
        // Trim whitespace so " 10.0.0.0/8" parses identically to "10.0.0.0/8".
        // inet_pton rejects whitespace, which would otherwise silently drop the
        // CIDR and break both runtime matching and policy equality.
        let trimmed = cidr.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let prefix = Int(parts[1]) else { return nil }
        let addr = String(parts[0])

        // Try IPv4 first, then IPv6.
        var sa4 = in_addr()
        if inet_pton(AF_INET, addr, &sa4) == 1 {
            guard prefix >= 0, prefix <= 32 else { return nil }
            addressBytes = Self.masked(bytes: withUnsafeBytes(of: sa4) { Array($0) }, prefixLength: prefix)
            prefixLength = prefix
            return
        }
        var sa6 = in6_addr()
        if inet_pton(AF_INET6, addr, &sa6) == 1 {
            guard prefix >= 0, prefix <= 128 else { return nil }
            addressBytes = Self.masked(bytes: withUnsafeBytes(of: sa6) { Array($0) }, prefixLength: prefix)
            prefixLength = prefix
            return
        }
        return nil
    }

    // MARK: Codable — encode as a canonical string, decode with validation

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let parsed = Self(raw) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid CIDR '\(raw)' — fix or delete the policy file"
            )
        }
        self = parsed
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }

    // MARK: Description — canonical "address/prefix" form (host bits masked)

    var description: String {
        let family = addressBytes.count == 4 ? AF_INET : AF_INET6
        let maxLen = addressBytes.count == 4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN
        var buf = [UInt8](repeating: 0, count: Int(maxLen))
        let ok = buf.withUnsafeMutableBufferPointer { dst -> Bool in
            dst.withMemoryRebound(to: CChar.self) { cDst in
                addressBytes.withUnsafeBufferPointer { src in
                    inet_ntop(family, src.baseAddress, cDst.baseAddress, socklen_t(maxLen)) != nil
                }
            }
        }
        guard ok, let nul = buf.firstIndex(of: 0) else {
            return "<invalid>/\(prefixLength)"
        }
        return "\(String(decoding: buf[..<nul], as: UTF8.self))/\(prefixLength)"
    }

    // MARK: Matching

    /// Test whether an IPv4 or IPv6 literal falls within this CIDR range.
    /// Returns false if the address can't be parsed or is in a different family.
    func contains(_ address: String) -> Bool {
        if addressBytes.count == 4 {
            var sa = in_addr()
            guard inet_pton(AF_INET, address, &sa) == 1 else { return false }
            return prefixMatches(withUnsafeBytes(of: sa) { Array($0) })
        }
        var sa6 = in6_addr()
        guard inet_pton(AF_INET6, address, &sa6) == 1 else { return false }
        return prefixMatches(withUnsafeBytes(of: sa6) { Array($0) })
    }

    private func prefixMatches(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == addressBytes.count else { return false }
        let fullBytes = prefixLength / 8
        let remainingBits = prefixLength % 8
        for i in 0 ..< fullBytes {
            if bytes[i] != addressBytes[i] { return false }
        }
        if remainingBits > 0 {
            let mask = UInt8(0xFF) << (8 - remainingBits)
            // addressBytes is pre-masked, so comparing masked input to raw stored byte works.
            if (bytes[fullBytes] & mask) != addressBytes[fullBytes] { return false }
        }
        return true
    }

    /// Zero out host bits beyond the prefix length so that e.g. 10.0.0.1/8 == 10.0.0.0/8.
    private static func masked(bytes: [UInt8], prefixLength: Int) -> [UInt8] {
        var result = bytes
        for i in 0 ..< result.count {
            let bitOffset = i * 8
            if bitOffset >= prefixLength {
                result[i] = 0
            } else if bitOffset + 8 > prefixLength {
                let bitsToKeep = prefixLength - bitOffset
                result[i] &= ~UInt8((1 << (8 - bitsToKeep)) - 1)
            }
        }
        return result
    }
}
