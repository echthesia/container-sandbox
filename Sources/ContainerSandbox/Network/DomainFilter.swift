import Foundation

/// Evaluates whether a host:port is allowed or denied by a network policy.
struct DomainFilter {
    let policy: NetworkPolicy

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
        if matchesAny(host: host, port: port, patterns: policy.blockedHosts) {
            return .deny(reason: "host explicitly blocked: \(host)")
        }

        switch policy.direction {
        case .deny:
            // Block by default; only allowed hosts pass.
            if matchesAny(host: host, port: port, patterns: policy.allowedHosts) {
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
        let trimmedCIDRs = policy.blockedCIDRs.map { $0.trimmingCharacters(in: .whitespaces) }
        for cidr in trimmedCIDRs {
            if cidrContains(cidr, address: ip) {
                return true
            }
        }
        // If the address is an IPv4-mapped IPv6 literal, also check the
        // embedded IPv4 against all CIDRs (catches e.g. ::ffff:10.0.0.5
        // against 10.0.0.0/8).
        if let v4 = extractMappedIPv4(ip) {
            for cidr in trimmedCIDRs {
                if cidrContains(cidr, address: v4) {
                    return true
                }
            }
        }
        return false
    }
}

// MARK: - Pattern matching

extension DomainFilter {
    /// Check if `host:port` matches any pattern in the list.
    ///
    /// Supported patterns:
    /// - `example.com` — exact host match, any port
    /// - `example.com:443` — exact host + port match
    /// - `*.example.com` — wildcard subdomain match, any port
    /// - `*.example.com:443` — wildcard subdomain + port match
    private func matchesAny(host: String, port: Int, patterns: [String]) -> Bool {
        for rawPattern in patterns {
            var pattern = rawPattern.trimmingCharacters(in: .whitespaces).lowercased()
            while pattern.hasSuffix(".") {
                pattern = String(pattern.dropLast())
            }
            if matches(host: host, port: port, pattern: pattern) {
                return true
            }
        }
        return false
    }

    private func matches(host: String, port: Int, pattern: String) -> Bool {
        let (patternHost, patternPort) = parseHostPort(pattern)

        // If pattern specifies a port, it must match.
        if let pp = patternPort, pp != port {
            return false
        }

        // Exact match.
        if patternHost == host {
            return true
        }

        // Wildcard match: *.example.com matches foo.example.com and bar.foo.example.com.
        if patternHost.hasPrefix("*.") {
            let suffix = String(patternHost.dropFirst(1)) // ".example.com"
            return host.hasSuffix(suffix) && host != String(suffix.dropFirst())
        }

        return false
    }
}

// MARK: - CIDR matching (uses POSIX inet_pton for robust address parsing)

extension DomainFilter {
    /// Check whether an address is an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    /// and return the embedded IPv4 string if so.
    private func extractMappedIPv4(_ ip: String) -> String? {
        guard let bytes = parseIPv6(ip) else { return nil }
        // IPv4-mapped: first 10 bytes zero, bytes 10-11 are 0xff.
        guard bytes[0 ..< 10].allSatisfy({ $0 == 0 }),
              bytes[10] == 0xFF, bytes[11] == 0xFF else { return nil }
        return "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
    }

    private func cidrContains(_ cidr: String, address: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2 else { return false }

        let network = String(parts[0])
        guard let prefixLen = Int(parts[1]) else { return false }

        // IPv4
        if let netAddr = parseIPv4(network), let addr = parseIPv4(address) {
            guard prefixLen >= 0, prefixLen <= 32 else { return false }
            let mask: UInt32 = prefixLen == 0 ? 0 : ~UInt32(0) << (32 - prefixLen)
            return (netAddr & mask) == (addr & mask)
        }

        // IPv6
        if let netBytes = parseIPv6(network), let addrBytes = parseIPv6(address) {
            guard prefixLen >= 0, prefixLen <= 128 else { return false }
            return prefixMatch(netBytes, addrBytes, bits: prefixLen)
        }

        return false
    }

    /// Parse an IPv4 address using inet_pton. Returns the address as a
    /// host-byte-order UInt32 (high byte = first octet), or nil on failure.
    private func parseIPv4(_ addr: String) -> UInt32? {
        var sa = in_addr()
        guard inet_pton(AF_INET, addr, &sa) == 1 else { return nil }
        return UInt32(bigEndian: sa.s_addr)
    }

    /// Parse an IPv6 address using inet_pton. Returns the 16-byte
    /// network-order representation, or nil on failure. Handles all
    /// standard forms: compressed (::), mapped (::ffff:a.b.c.d), etc.
    private func parseIPv6(_ addr: String) -> [UInt8]? {
        var sa6 = in6_addr()
        guard inet_pton(AF_INET6, addr, &sa6) == 1 else { return nil }
        return withUnsafeBytes(of: sa6) { Array($0) }
    }

    private func prefixMatch(_ a: [UInt8], _ b: [UInt8], bits: Int) -> Bool {
        let fullBytes = bits / 8
        let remainingBits = bits % 8

        for i in 0 ..< fullBytes {
            if a[i] != b[i] { return false }
        }

        if remainingBits > 0 {
            let mask = UInt8(0xFF) << (8 - remainingBits)
            if (a[fullBytes] & mask) != (b[fullBytes] & mask) { return false }
        }

        return true
    }
}
