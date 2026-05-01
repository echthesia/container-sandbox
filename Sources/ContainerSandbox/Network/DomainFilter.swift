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
        let host = Self.normalizeHostPattern(host)
        // Parse the host string once; both list checks below reuse the result
        // so we don't run inet_pton twice per request in deny mode.
        let resolved = Self.resolveHost(host)

        if matchesHost(resolved, port: port, in: blocked) {
            return .deny(reason: "host explicitly blocked: \(host)")
        }

        switch policy.direction {
        case .deny:
            if matchesHost(resolved, port: port, in: allowed) {
                return .allow
            }
            return .deny(reason: "host not in allowlist: \(host)")

        case .allow:
            return .allow
        }
    }

    /// Post-DNS check for a resolved peer IP: returns true if the address is
    /// blocked by either an explicit IP entry in `blockedHosts` or any
    /// `blockedCIDRs` rule. The upfront `evaluate` call already covers IP
    /// literals supplied as the request target; this catches the DNS-rebinding
    /// case where a hostname resolves to an IP we want to block.
    func isBlockedResolvedIP(_ ip: String, port: Int) -> Bool {
        // blockedHosts may contain IP entries (parsed into blocked.ipv4s/ipv6s
        // at init time). Reuse the existing host-matching path so IPv4-mapped
        // IPv6 normalization and port-scoped entries behave the same as in
        // the upfront evaluate() call.
        let resolved = Self.resolveHost(ip)
        if matchesHost(resolved, port: port, in: blocked) {
            return true
        }
        return isBlockedCIDR(ip)
    }

    /// Check whether a resolved IP address falls within any blocked CIDR range.
    /// Also detects IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) and checks
    /// the embedded IPv4 against IPv4 CIDRs.
    func isBlockedCIDR(_ ip: String) -> Bool {
        // Parse the input once and reuse the bytes across every CIDR check —
        // the default policy ships with 8 CIDRs, so re-parsing per check would
        // run inet_pton an order of magnitude more often than necessary.
        let ipBytes: [UInt8]
        var sa4 = in_addr()
        if inet_pton(AF_INET, ip, &sa4) == 1 {
            ipBytes = withUnsafeBytes(of: sa4) { Array($0) }
        } else {
            var sa6 = in6_addr()
            guard inet_pton(AF_INET6, ip, &sa6) == 1 else { return false }
            ipBytes = withUnsafeBytes(of: sa6) { Array($0) }
        }

        for cidr in policy.blockedCIDRs where cidr.contains(bytes: ipBytes) {
            return true
        }
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) — also test the embedded IPv4
        // bytes against IPv4 CIDRs (catches e.g. ::ffff:10.0.0.5 vs 10.0.0.0/8).
        if ipBytes.count == 16, Self.mappedIPv4(ipBytes) != nil {
            let v4Bytes = Array(ipBytes[12..<16])
            for cidr in policy.blockedCIDRs where cidr.contains(bytes: v4Bytes) {
                return true
            }
        }
        return false
    }
}

// MARK: - Host normalization

extension DomainFilter {
    /// Canonicalize a host or host-pattern: trim whitespace, lowercase,
    /// strip trailing dots. Two strings that differ only in these respects
    /// must compare equal so policy matching and policy equality agree.
    static func normalizeHostPattern(_ raw: String) -> String {
        var h = raw.trimmingCharacters(in: .whitespaces).lowercased()
        while h.hasSuffix(".") {
            h = String(h.dropLast())
        }
        return h
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
            let pattern = normalizeHostPattern(rawPattern)
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

    /// Discriminated form of a request host so callers can parse once and
    /// dispatch many times. IPv4-mapped IPv6 (::ffff:a.b.c.d) is normalized
    /// at parse time so it matches plain IPv4 entries in either direction
    /// (RFC 4291 §2.5.5.2).
    enum ResolvedHost {
        case ipv4(UInt32)
        case ipv6(bytes: [UInt8])
        case domain(String)
    }

    static func resolveHost(_ host: String) -> ResolvedHost {
        var sa4 = in_addr()
        if inet_pton(AF_INET, host, &sa4) == 1 {
            return .ipv4(UInt32(bigEndian: sa4.s_addr))
        }
        var sa6 = in6_addr()
        if inet_pton(AF_INET6, host, &sa6) == 1 {
            let bytes = withUnsafeBytes(of: sa6) { Array($0) }
            if let v4 = mappedIPv4(bytes) {
                return .ipv4(v4)
            }
            return .ipv6(bytes: bytes)
        }
        return .domain(host)
    }

    /// Match a pre-resolved host against pre-parsed host entries.
    private func matchesHost(_ resolved: ResolvedHost, port: Int, in hosts: ParsedHosts) -> Bool {
        switch resolved {
        case .ipv4(let addr):
            return hosts.ipv4s.contains { entry in
                (entry.port == nil || entry.port == port) && entry.addr == addr
            }
        case .ipv6(let bytes):
            return hosts.ipv6s.contains { entry in
                (entry.port == nil || entry.port == port) && entry.addr == bytes
            }
        case .domain(let host):
            return matchesDomain(host: host, port: port, patterns: hosts.domains)
        }
    }

    /// Return the embedded IPv4 (host byte order) if `bytes` is an IPv4-mapped
    /// IPv6 address (::ffff:a.b.c.d), else nil.
    static func mappedIPv4(_ bytes: [UInt8]) -> UInt32? {
        guard bytes.count == 16,
            bytes[0..<10].allSatisfy({ $0 == 0 }),
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
                let suffix = String(entry.pattern.dropFirst(1))  // ".example.com"
                if host.hasSuffix(suffix) && host != String(suffix.dropFirst()) {
                    return true
                }
            }
        }
        return false
    }
}
