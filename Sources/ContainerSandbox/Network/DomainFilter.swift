import Foundation

/// Evaluates whether a host:port is allowed or denied by a network policy.
struct DomainFilter: Sendable {
    let policy: NetworkPolicy

    enum Decision: Equatable, Sendable {
        case allow
        case deny(reason: String)
    }

    /// Evaluate whether a connection to `host:port` should be allowed.
    func evaluate(host: String, port: Int) -> Decision {
        let host = host.lowercased()

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
    func isBlockedCIDR(_ ip: String) -> Bool {
        for cidr in policy.blockedCIDRs {
            if cidrContains(cidr, address: ip) {
                return true
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
        for pattern in patterns {
            if matches(host: host, port: port, pattern: pattern.lowercased()) {
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

    /// Split "host:port" or "host" into components.
    private func parseHostPort(_ pattern: String) -> (host: String, port: Int?) {
        // Handle IPv6 in brackets: [::1]:443
        if pattern.hasPrefix("["), let bracketEnd = pattern.firstIndex(of: "]") {
            let host = String(pattern[pattern.index(after: pattern.startIndex)...pattern.index(before: bracketEnd)])
            let afterBracket = pattern[pattern.index(after: bracketEnd)...]
            if afterBracket.hasPrefix(":"), let port = Int(afterBracket.dropFirst()) {
                return (host, port)
            }
            return (host, nil)
        }

        // Wildcard or regular host — split on last colon only if the suffix is a valid port.
        if let lastColon = pattern.lastIndex(of: ":") {
            let possiblePort = String(pattern[pattern.index(after: lastColon)...])
            if let port = Int(possiblePort) {
                return (String(pattern[..<lastColon]), port)
            }
        }

        return (pattern, nil)
    }
}

// MARK: - CIDR matching

extension DomainFilter {
    /// Check if an IPv4 address is within a CIDR range.
    private func cidrContains(_ cidr: String, address: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2 else { return false }

        let network = String(parts[0])
        guard let prefixLen = Int(parts[1]) else { return false }

        // IPv4
        if let netAddr = ipv4ToUInt32(network), let addr = ipv4ToUInt32(address) {
            guard prefixLen >= 0, prefixLen <= 32 else { return false }
            let mask: UInt32 = prefixLen == 0 ? 0 : ~UInt32(0) << (32 - prefixLen)
            return (netAddr & mask) == (addr & mask)
        }

        // IPv6 — simple prefix comparison on expanded form.
        if let netBytes = ipv6ToBytes(network), let addrBytes = ipv6ToBytes(address) {
            guard prefixLen >= 0, prefixLen <= 128 else { return false }
            return prefixMatch(netBytes, addrBytes, bits: prefixLen)
        }

        return false
    }

    private func ipv4ToUInt32(_ addr: String) -> UInt32? {
        let octets = addr.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4 else { return nil }
        return UInt32(octets[0]) << 24 | UInt32(octets[1]) << 16 | UInt32(octets[2]) << 8 | UInt32(octets[3])
    }

    private func ipv6ToBytes(_ addr: String) -> [UInt8]? {
        var groups = addr.split(separator: ":", omittingEmptySubsequences: false).map(String.init)

        // Expand :: shorthand.
        if let emptyIdx = groups.firstIndex(of: "") {
            // Handle leading/trailing :: producing extra empty strings.
            let nonEmpty = groups.filter { !$0.isEmpty }
            let missing = 8 - nonEmpty.count
            guard missing >= 0 else { return nil }
            groups.remove(at: emptyIdx)
            for _ in 0..<missing {
                groups.insert("0", at: emptyIdx)
            }
            // Remove any remaining empty strings from leading/trailing ::
            groups = groups.filter { !$0.isEmpty }
        }

        guard groups.count == 8 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        for group in groups {
            guard let val = UInt16(group, radix: 16) else { return nil }
            bytes.append(UInt8(val >> 8))
            bytes.append(UInt8(val & 0xFF))
        }
        return bytes
    }

    private func prefixMatch(_ a: [UInt8], _ b: [UInt8], bits: Int) -> Bool {
        let fullBytes = bits / 8
        let remainingBits = bits % 8

        for i in 0..<fullBytes {
            if a[i] != b[i] { return false }
        }

        if remainingBits > 0 {
            let mask = UInt8(0xFF) << (8 - remainingBits)
            if (a[fullBytes] & mask) != (b[fullBytes] & mask) { return false }
        }

        return true
    }
}
