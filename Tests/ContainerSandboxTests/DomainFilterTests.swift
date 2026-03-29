@testable import sandbox
import Testing

struct DomainFilterTests {
    // MARK: - Deny mode (block by default, allow listed)

    @Test func denyModeBlocksUnlisted() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["api.anthropic.com"]))
        let result = filter.evaluate(host: "google.com", port: 443)
        #expect(result == .deny(reason: "host not in allowlist: google.com"))
    }

    @Test func denyModeAllowsListed() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["api.anthropic.com"]))
        #expect(filter.evaluate(host: "api.anthropic.com", port: 443) == .allow)
    }

    @Test func wildcardMatchesSubdomain() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.anthropic.com"]))
        #expect(filter.evaluate(host: "api.anthropic.com", port: 443) == .allow)
        #expect(filter.evaluate(host: "docs.anthropic.com", port: 80) == .allow)
        #expect(filter.evaluate(host: "deep.sub.anthropic.com", port: 443) == .allow)
    }

    @Test func wildcardDoesNotMatchBase() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.anthropic.com"]))
        // *.example.com should NOT match example.com itself
        #expect(filter.evaluate(host: "anthropic.com", port: 443) != .allow)
    }

    @Test func portSpecificMatch() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["api.example.com:443"]))
        #expect(filter.evaluate(host: "api.example.com", port: 443) == .allow)
        #expect(filter.evaluate(host: "api.example.com", port: 80) != .allow)
    }

    @Test func wildcardWithPort() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com:443"]))
        #expect(filter.evaluate(host: "api.example.com", port: 443) == .allow)
        #expect(filter.evaluate(host: "api.example.com", port: 80) != .allow)
    }

    @Test func caseInsensitive() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["API.Anthropic.COM"]))
        #expect(filter.evaluate(host: "api.anthropic.com", port: 443) == .allow)
    }

    // MARK: - Allow mode (allow by default, block listed)

    @Test func allowModeAllowsUnlisted() {
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["evil.com"],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "google.com", port: 443) == .allow)
    }

    @Test func allowModeBlocksListed() {
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["evil.com"],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "evil.com", port: 443) != .allow)
    }

    // MARK: - Blocked hosts always checked

    @Test func blockedHostsOverrideAllowedInDenyMode() {
        let policy = NetworkPolicy.deny(
            allowedHosts: ["*.example.com"],
            blockedHosts: ["bad.example.com"]
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "good.example.com", port: 443) == .allow)
        #expect(filter.evaluate(host: "bad.example.com", port: 443) != .allow)
    }

    // MARK: - IP host matching (binary comparison, format-insensitive)

    @Test func ipv4InAllowlist() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["10.0.0.1"]))
        #expect(filter.evaluate(host: "10.0.0.1", port: 443) == .allow)
        #expect(filter.evaluate(host: "10.0.0.2", port: 443) != .allow)
    }

    @Test func ipv4InBlocklist() {
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["10.0.0.1"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "10.0.0.1", port: 443) != .allow)
        #expect(filter.evaluate(host: "10.0.0.2", port: 443) == .allow)
    }

    @Test func ipv6CanonicalMatchesExpanded() {
        // "::1" in the allowlist should match the expanded form "0:0:0:0:0:0:0:1"
        // (the format SOCKS5 handler produces). Both parse to the same binary via inet_pton.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["::1"]))
        #expect(filter.evaluate(host: "::1", port: 443) == .allow)
        #expect(filter.evaluate(host: "0:0:0:0:0:0:0:1", port: 443) == .allow)
        #expect(filter.evaluate(host: "0000:0000:0000:0000:0000:0000:0000:0001", port: 443) == .allow)
        #expect(filter.evaluate(host: "::2", port: 443) != .allow)
    }

    @Test func ipv6InBlocklist() {
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["::1"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "::1", port: 443) != .allow)
        #expect(filter.evaluate(host: "0:0:0:0:0:0:0:1", port: 443) != .allow)
    }

    @Test func ipWithPortInHostList() {
        // "10.0.0.1:443" should only match on port 443
        let filter = DomainFilter(policy: .deny(allowedHosts: ["10.0.0.1:443"]))
        #expect(filter.evaluate(host: "10.0.0.1", port: 443) == .allow)
        #expect(filter.evaluate(host: "10.0.0.1", port: 80) != .allow)
    }

    @Test func bracketedIPv6WithPort() {
        // "[::1]:443" should match ::1 on port 443 only
        let filter = DomainFilter(policy: .deny(allowedHosts: ["[::1]:443"]))
        #expect(filter.evaluate(host: "::1", port: 443) == .allow)
        #expect(filter.evaluate(host: "::1", port: 80) != .allow)
        #expect(filter.evaluate(host: "0:0:0:0:0:0:0:1", port: 443) == .allow)
    }

    @Test func ipDoesNotMatchDomainPattern() {
        // An IP address should not match a domain wildcard
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.0.0.1"]))
        #expect(filter.evaluate(host: "127.0.0.1", port: 443) != .allow)
    }

    // MARK: - CIDR blocking

    @Test func ipv4CIDRBlocking() {
        let filter = DomainFilter(policy: .deny)
        #expect(filter.isBlockedCIDR("10.0.0.1"))
        #expect(filter.isBlockedCIDR("172.16.5.10"))
        #expect(filter.isBlockedCIDR("192.168.1.1"))
        #expect(filter.isBlockedCIDR("127.0.0.1"))
    }

    @Test func publicIPNotBlocked() {
        let filter = DomainFilter(policy: .deny)
        #expect(!filter.isBlockedCIDR("8.8.8.8"))
        #expect(!filter.isBlockedCIDR("1.1.1.1"))
    }

    // MARK: - IPv6 CIDR blocking

    @Test func ipv6LoopbackBlocked() {
        let filter = DomainFilter(policy: .deny)
        // ::1/128 — exact loopback
        #expect(filter.isBlockedCIDR("::1"))
        #expect(filter.isBlockedCIDR("0000:0000:0000:0000:0000:0000:0000:0001"))
    }

    @Test func ipv6UniqueLocalBlocked() {
        let filter = DomainFilter(policy: .deny)
        // fc00::/7 covers fc00:: through fdff::
        #expect(filter.isBlockedCIDR("fc00::1"))
        #expect(filter.isBlockedCIDR("fd00::1"))
        #expect(filter.isBlockedCIDR("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
    }

    @Test func ipv6LinkLocalBlocked() {
        let filter = DomainFilter(policy: .deny)
        // fe80::/10 covers fe80:: through febf::
        #expect(filter.isBlockedCIDR("fe80::1"))
        #expect(filter.isBlockedCIDR("fe80::1234:5678"))
        #expect(filter.isBlockedCIDR("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
        // fec0:: is outside fe80::/10 (first 10 bits differ)
        #expect(!filter.isBlockedCIDR("fec0::1"))
    }

    @Test func ipv6PublicNotBlocked() {
        let filter = DomainFilter(policy: .deny)
        #expect(!filter.isBlockedCIDR("2001:db8::1"))
        #expect(!filter.isBlockedCIDR("2607:f8b0:4004:800::200e"))
    }

    @Test func ipv6LoopbackDoesNotMatchWrongAddress() {
        let filter = DomainFilter(policy: .deny)
        // ::1/128 is exact — ::2 should NOT be blocked by that rule alone
        // (but might be blocked by fc00::/7 or other rules — ::2 is not in any of them)
        #expect(!filter.isBlockedCIDR("::2"))
    }

    // MARK: - IPv4-mapped IPv6

    @Test func ipv4MappedIPv6LoopbackBlocked() {
        let filter = DomainFilter(policy: .deny)
        // ::ffff:127.0.0.1 maps to 127.0.0.1, blocked by 127.0.0.0/8
        #expect(filter.isBlockedCIDR("::ffff:127.0.0.1"))
    }

    @Test func ipv4MappedIPv6PrivateBlocked() {
        let filter = DomainFilter(policy: .deny)
        #expect(filter.isBlockedCIDR("::ffff:10.0.0.5"))
        #expect(filter.isBlockedCIDR("::ffff:192.168.1.1"))
        #expect(filter.isBlockedCIDR("::ffff:172.16.0.1"))
    }

    @Test func ipv4MappedIPv6PublicNotBlocked() {
        let filter = DomainFilter(policy: .deny)
        #expect(!filter.isBlockedCIDR("::ffff:8.8.8.8"))
        #expect(!filter.isBlockedCIDR("::ffff:1.1.1.1"))
    }

    @Test func ipv4MappedIPv6HexFormBlocked() {
        let filter = DomainFilter(policy: .deny)
        // ::ffff:7f00:1 is the pure-hex form of ::ffff:127.0.0.1
        #expect(filter.isBlockedCIDR("::ffff:7f00:1"))
    }

    // MARK: - Edge cases

    @Test func emptyAllowlistDeniesAll() {
        let filter = DomainFilter(policy: .deny)
        // defaultAllowedHosts are still allowed
        #expect(filter.evaluate(host: "anything.com", port: 443) != .allow)
    }

    @Test func multipleAllowedHosts() {
        let filter = DomainFilter(policy: .deny(allowedHosts: [
            "*.github.com", "registry.npmjs.org",
        ]))
        #expect(filter.evaluate(host: "api.anthropic.com", port: 443) == .allow)
        #expect(filter.evaluate(host: "raw.github.com", port: 443) == .allow)
        #expect(filter.evaluate(host: "registry.npmjs.org", port: 443) == .allow)
        #expect(filter.evaluate(host: "evil.com", port: 443) != .allow)
    }

    // MARK: - Adversarial: trailing dot bypass

    @Test func trailingDotShouldNotBypassExactMatch() {
        // DNS canonical form uses trailing dot — "example.com." and "example.com"
        // are the same host, so an allowed host should match with or without the dot.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com"]))
        #expect(filter.evaluate(host: "example.com.", port: 443) == .allow)
    }

    @Test func trailingDotBypassesWildcardBaseExclusion() {
        // *.example.com has a guard preventing it from matching "example.com".
        // But "example.com." passes the guard (different string) while still
        // matching the ".example.com" suffix. This is a security bypass.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com"]))
        // The wildcard should NOT match the base domain, even with a trailing dot
        #expect(filter.evaluate(host: "example.com.", port: 443) != .allow)
    }

    // MARK: - Adversarial: wildcard edge cases

    @Test func bareWildcardMatchesNothing() {
        // "*" alone doesn't have the "*." prefix, so it only matches literal "*"
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*"]))
        #expect(filter.evaluate(host: "anything.com", port: 443) != .allow)
    }

    @Test func wildcardDotMatchesNothing() {
        // "*." — suffix is "", so host.hasSuffix("") is always true,
        // but guard host != "" might save us. Test what actually happens.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*."]))
        // Any non-empty host would match suffix "" — this is a potential open wildcard
        #expect(filter.evaluate(host: "anything.com", port: 443) != .allow)
    }

    @Test func doubleDotSubdomain() {
        // "..example.com" is a malformed subdomain
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com"]))
        // hasSuffix(".example.com") is true for "..example.com"
        #expect(filter.evaluate(host: "..example.com", port: 443) == .allow)
    }

    @Test func emptyHostEvaluation() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com"]))
        #expect(filter.evaluate(host: "", port: 443) != .allow)
    }

    @Test func emptyHostWithEmptyAllowlistEntry() {
        // Empty pattern "" in the allowlist matches empty host "" via exact string match.
        // This is arguably correct (exact match works) but surprising — an empty
        // string in the allowlist acts as an escape hatch for empty hosts.
        let filter = DomainFilter(policy: .deny(allowedHosts: [""]))
        #expect(filter.evaluate(host: "", port: 443) == .allow)
    }

    @Test func trailingDotBypassesBlocklistInAllowMode() {
        // In allow mode, the blocklist is checked first. A trailing dot on the host
        // prevents the suffix/exact match from finding the blocked host.
        // This means "example.com." bypasses a block on "example.com"
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["evil.com"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "evil.com", port: 443) != .allow)
        // BUG: trailing dot bypasses the blocklist
        #expect(filter.evaluate(host: "evil.com.", port: 443) != .allow)
    }

    @Test func trailingDotBypassesWildcardBlocklist() {
        // Same bypass but with wildcard: *.evil.com blocks sub.evil.com
        // but sub.evil.com. bypasses because hasSuffix(".evil.com") fails
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["*.evil.com"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "sub.evil.com", port: 443) != .allow)
        // BUG: trailing dot bypasses wildcard blocklist
        #expect(filter.evaluate(host: "sub.evil.com.", port: 443) != .allow)
    }

    // MARK: - Adversarial: blocked host patterns

    @Test func blockedHostPortSpecific() {
        // Block evil.com only on port 443 — other ports should be allowed
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["evil.com:443"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "evil.com", port: 443) != .allow)
        #expect(filter.evaluate(host: "evil.com", port: 80) == .allow)
    }

    @Test func blockedHostWildcardWithPort() {
        // *.evil.com:443 should block subdomains on 443 but not on 80
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["*.evil.com:443"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "sub.evil.com", port: 443) != .allow)
        #expect(filter.evaluate(host: "sub.evil.com", port: 80) == .allow)
    }

    // MARK: - Adversarial: CIDR boundary conditions

    @Test(arguments: [
        // 10.0.0.0/8 boundaries
        ("10.0.0.0", true, "first addr in 10.0.0.0/8"),
        ("10.255.255.255", true, "last addr in 10.0.0.0/8"),
        ("11.0.0.0", false, "first addr outside 10.0.0.0/8"),
        ("9.255.255.255", false, "just below 10.0.0.0/8"),
        // 172.16.0.0/12 boundaries
        ("172.16.0.0", true, "first addr in 172.16.0.0/12"),
        ("172.31.255.255", true, "last addr in 172.16.0.0/12"),
        ("172.32.0.0", false, "first addr outside 172.16.0.0/12"),
        ("172.15.255.255", false, "just below 172.16.0.0/12"),
        // 192.168.0.0/16 boundaries
        ("192.168.0.0", true, "first addr in 192.168.0.0/16"),
        ("192.168.255.255", true, "last addr in 192.168.0.0/16"),
        ("192.169.0.0", false, "first addr outside 192.168.0.0/16"),
        ("192.167.255.255", false, "just below 192.168.0.0/16"),
        // 169.254.0.0/16 (link-local)
        ("169.254.0.1", true, "link-local"),
        ("169.254.169.254", true, "cloud metadata endpoint"),
        ("169.255.0.0", false, "just outside link-local"),
    ])
    func cidrBoundaryConditions(ip: String, shouldBeBlocked: Bool, label: String) {
        let filter = DomainFilter(policy: .deny)
        #expect(
            filter.isBlockedCIDR(ip) == shouldBeBlocked,
            "Expected \(ip) (\(label)) to be \(shouldBeBlocked ? "blocked" : "allowed")"
        )
    }

    // MARK: - Adversarial: CIDR special cases

    @Test func cidrSlashZeroMatchesEverything() {
        // /0 prefix means match all — mask is 0
        let policy = NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: ["0.0.0.0/0"]
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedCIDR("8.8.8.8"))
        #expect(filter.isBlockedCIDR("1.2.3.4"))
    }

    @Test func cidrSlash32ExactMatchOnly() {
        let policy = NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: ["1.2.3.4/32"]
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedCIDR("1.2.3.4"))
        #expect(!filter.isBlockedCIDR("1.2.3.5"))
    }

    @Test func garbageCIDRHandledGracefully() {
        let policy = NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: ["not-a-cidr/8", "also garbage", "/32", ""]
        )
        let filter = DomainFilter(policy: policy)
        // Should not crash, should not block anything
        #expect(!filter.isBlockedCIDR("8.8.8.8"))
    }

    @Test func ipv4MappedHexFormBlocked() {
        // ::ffff:0a00:0001 is the pure-hex encoding of ::ffff:10.0.0.1
        let filter = DomainFilter(policy: .deny)
        #expect(filter.isBlockedCIDR("::ffff:0a00:0001"))
    }

    @Test func uppercaseHexInIPv4MappedBlocked() {
        // isBlockedCIDR doesn't lowercase — verify inet_pton handles uppercase
        let filter = DomainFilter(policy: .deny)
        #expect(filter.isBlockedCIDR("::FFFF:10.0.0.1"))
    }

    @Test func ipv6Slash128ExactMatch() {
        // ::1/128 should only match exactly ::1
        let filter = DomainFilter(policy: .deny)
        #expect(filter.isBlockedCIDR("::1"))
        #expect(!filter.isBlockedCIDR("::2"))
    }
}
