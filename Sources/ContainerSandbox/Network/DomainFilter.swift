import Foundation

/// Evaluates whether a host:port is allowed or denied by a network policy.
struct DomainFilter {
    let policy: NetworkPolicy

    /// Pre-parsed host entries from allowedHosts/blockedHosts, separated by type.
    /// IPs are stored in binary form for format-insensitive comparison (e.g. "::1"
    /// matches "0:0:0:0:0:0:0:1"). Domain patterns stay as strings.
    private let allowed: ParsedHosts
    private let blocked: ParsedHosts

    init(policy: NetworkPolicy) {
        self.policy = policy
        allowed = Self.parseHosts(policy.allowedHosts)
        blocked = Self.parseHosts(policy.blockedHosts)
    }

    enum Decision: Equatable {
        case allow
        case deny(reason: String)
    }

    /// Evaluate whether a connection to `host:port` should be allowed.
    func evaluate(host: String, port: Int) -> Decision {
        var host = host.lowercased()
        while host.hasSuffix(".") {
            host = String(host.dropLast())
        }

        // Always check blocked hosts first (both directions).
        if matchesHost(host, port: port, in: blocked) {
            return .deny(reason: "host explicitly blocked: \(host)")
        }

        switch policy.direction {
        case .deny:
            // Block by default; only allowed hosts pass.
            if matchesHost(host, port: port, in: allowed) {
                return .allow
            }
            return .deny(reason: "host not in allowlist: \(host)")

        case .allow:
            // Allow by default; only blocked hosts (checked above) are denied.
            return .allow
        }
    }

    /// Check whether a resolved IP address falls within any blocked CIDR range.
    /// Also detects IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) and checks
    /// the embedded IPv4 against IPv4 CIDRs.
    func isBlockedCIDR(_ ip: String) -> Bool {
        for cidr in policy.blockedCIDRs where cidr.contains(ip) {
            return true
        }
        // If the address is an IPv4-mapped IPv6 literal, also check the
        // embedded IPv4 against all CIDRs (catches e.g. ::ffff:10.0.0.5
        // against 10.0.0.0/8).
        if let v4 = extractMappedIPv4(ip) {
            for cidr in policy.blockedCIDRs where cidr.contains(v4) {
                return true
            }
        }
        return false
    }
}

// MARK: - Host list parsing and matching

extension DomainFilter {
    /// Pre-parsed host entries separated into IPs (binary) and domain patterns (string).
    private struct ParsedHosts {
        var domains: [(pattern: String, port: Int?)]
        var ipv4s: [(addr: UInt32, port: Int?)]
        var ipv6s: [(addr: [UInt8], port: Int?)]

        static let empty = ParsedHosts(domains: [], ipv4s: [], ipv6s: [])
    }

    /// Parse host patterns, separating IPs from domain names.
    /// IP entries are stored as binary (via inet_pton) for format-insensitive matching.
    private static func parseHosts(_ patterns: [String]) -> ParsedHosts {
        var result = ParsedHosts.empty
        for rawPattern in patterns {
            var pattern = rawPattern.trimmingCharacters(in: .whitespaces).lowercased()
            while pattern.hasSuffix(".") {
                pattern = String(pattern.dropLast())
            }
            let (host, port) = parseHostPort(pattern)

            // Try IPv4
            var sa4 = in_addr()
            if inet_pton(AF_INET, host, &sa4) == 1 {
                result.ipv4s.append((UInt32(bigEndian: sa4.s_addr), port))
                continue
            }
            // Try IPv6. Canonicalize IPv4-mapped addresses (::ffff:a.b.c.d) to
            // their embedded IPv4 so they match plain IPv4 entries (RFC 4291 §2.5.5.2).
            var sa6 = in6_addr()
            if inet_pton(AF_INET6, host, &sa6) == 1 {
                let bytes = withUnsafeBytes(of: sa6) { Array($0) }
                if let v4 = mappedIPv4(bytes) {
                    result.ipv4s.append((v4, port))
                } else {
                    result.ipv6s.append((bytes, port))
                }
                continue
            }
            // Domain pattern
            result.domains.append((host, port))
        }
        return result
    }

    /// Match a host against pre-parsed host entries.
    /// If the host is an IP, matches against IP entries using binary comparison.
    /// If it's a domain, matches against domain patterns using string comparison.
    private func matchesHost(_ host: String, port: Int, in hosts: ParsedHosts) -> Bool {
        // Try as IPv4
        var sa4 = in_addr()
        if inet_pton(AF_INET, host, &sa4) == 1 {
            let addr = UInt32(bigEndian: sa4.s_addr)
            return hosts.ipv4s.contains { entry in
                (entry.port == nil || entry.port == port) && entry.addr == addr
            }
        }
        // Try as IPv6. IPv4-mapped addresses are canonicalized to IPv4 so they
        // match plain IPv4 entries in either direction (RFC 4291 §2.5.5.2).
        var sa6 = in6_addr()
        if inet_pton(AF_INET6, host, &sa6) == 1 {
            let bytes = withUnsafeBytes(of: sa6) { Array($0) }
            if let v4 = Self.mappedIPv4(bytes) {
                return hosts.ipv4s.contains { entry in
                    (entry.port == nil || entry.port == port) && entry.addr == v4
                }
            }
            return hosts.ipv6s.contains { entry in
                (entry.port == nil || entry.port == port) && entry.addr == bytes
            }
        }
        // Domain matching
        return matchesDomain(host: host, port: port, patterns: hosts.domains)
    }

    /// Return the embedded IPv4 (host byte order) if `bytes` is an IPv4-mapped
    /// IPv6 address (::ffff:a.b.c.d), else nil.
    static func mappedIPv4(_ bytes: [UInt8]) -> UInt32? {
        guard bytes.count == 16,
              bytes[0 ..< 10].allSatisfy({ $0 == 0 }),
              bytes[10] == 0xFF, bytes[11] == 0xFF
        else { return nil }
        return (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16) | (UInt32(bytes[14]) << 8) | UInt32(bytes[15])
    }

    /// Match a domain name against domain patterns (exact or wildcard).
    private func matchesDomain(host: String, port: Int, patterns: [(pattern: String, port: Int?)]) -> Bool {
        for entry in patterns {
            // If pattern specifies a port, it must match.
            if let pp = entry.port, pp != port { continue }

            // Exact match.
            if entry.pattern == host { return true }

            // Wildcard match: *.example.com matches foo.example.com and bar.foo.example.com.
            if entry.pattern.hasPrefix("*.") {
                let suffix = String(entry.pattern.dropFirst(1)) // ".example.com"
                if host.hasSuffix(suffix) && host != String(suffix.dropFirst()) {
                    return true
                }
            }
        }
        return false
    }
}

// MARK: - IPv4-mapped IPv6 extraction (used by both host and CIDR matching)

extension DomainFilter {
    /// Check whether an address is an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    /// and return the embedded IPv4 string if so.
    private func extractMappedIPv4(_ ip: String) -> String? {
        var sa6 = in6_addr()
        guard inet_pton(AF_INET6, ip, &sa6) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: sa6) { Array($0) }
        guard bytes[0 ..< 10].allSatisfy({ $0 == 0 }),
              bytes[10] == 0xFF, bytes[11] == 0xFF
        else { return nil }
        return "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
    }
}
