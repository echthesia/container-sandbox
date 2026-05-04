import Foundation
import Testing

@testable import sandbox

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
        let filter = DomainFilter(
            policy: .deny(allowedHosts: [
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

    @Test func doubleDotSubdomainRejected() {
        // "..example.com" is a malformed subdomain (empty label between
        // the two dots). hasSuffix(".example.com") matches mechanically,
        // but the label-presence guard rejects empty/leading-dot prefixes.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com"]))
        #expect(filter.evaluate(host: "..example.com", port: 443) != .allow)
    }

    @Test func leadingDotSubdomainRejected() {
        // ".example.com" — the wildcard's base-domain guard catches the
        // exact base, but a single leading dot needs the label-presence
        // guard to reject.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com"]))
        #expect(filter.evaluate(host: ".example.com", port: 443) != .allow)
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

    @Test func cidrSlashZeroMatchesEverything() throws {
        // /0 prefix means match all — mask is 0
        let policy = try NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("0.0.0.0/0"))]
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedCIDR("8.8.8.8"))
        #expect(filter.isBlockedCIDR("1.2.3.4"))
    }

    @Test func cidrSlash32ExactMatchOnly() throws {
        let policy = try NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("1.2.3.4/32"))]
        )
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedCIDR("1.2.3.4"))
        #expect(!filter.isBlockedCIDR("1.2.3.5"))
    }

    @Test func garbageCIDRRejectedAtConstructionAndDecode() {
        // With blockedCIDRs: [NormalizedCIDR], garbage can't enter the policy:
        // NormalizedCIDR init is failable, and JSON decode wraps that failure.
        for garbage in ["not-a-cidr/8", "also garbage", "/32", "", "10.0.0.0", "10.0.0.0/33"] {
            #expect(NormalizedCIDR(garbage) == nil, "Should reject '\(garbage)'")
        }
        let json = #"{"direction":"deny","allowedHosts":[],"blockedHosts":[],"blockedCIDRs":["not-a-cidr/8"]}"#
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(NetworkPolicy.self, from: Data(json.utf8))
        }
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

    // MARK: - Adversarial: control characters in hostnames
    //
    // Swift String permits embedded U+0000. NIO's connect-by-host flows the
    // string into libc getaddrinfo via Swift's automatic C-string bridging,
    // which truncates at the first NUL — so a host like "evil.com\0.example.com"
    // would resolve as "evil.com" while the Swift filter (which sees the full
    // string) matches a "*.example.com" allowlist via hasSuffix. Same risk
    // applies to bare CR / LF / other CTL chars that round-trip differently
    // through different parsers. evaluate() rejects these up front.

    @Test func nulByteHostnameDoesNotMatchWildcard() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com"]))
        #expect(filter.evaluate(host: "evil.com\u{0}.example.com", port: 443) != .allow)
    }

    @Test func crLfInHostnameRejected() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com"]))
        #expect(filter.evaluate(host: "example.com\r\n", port: 443) != .allow)
        #expect(filter.evaluate(host: "example.com\n", port: 443) != .allow)
        #expect(filter.evaluate(host: "exam\rple.com", port: 443) != .allow)
    }

    @Test func delByteInHostnameRejected() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com"]))
        // 0x7F (DEL) is in the same control-character class.
        #expect(filter.evaluate(host: "example.com\u{7F}", port: 443) != .allow)
    }

    // MARK: - Adversarial: pre-connect CIDR check for IP literals
    //
    // The post-connect resolvedBlockedIP catches DNS rebinding, but for an
    // IP-literal target the proxy used to issue a TCP SYN before checking.
    // That leaks an open/closed/RST signal, allowing an agent in .allow mode
    // to scan host loopback / RFC1918 / cloud-metadata addresses. evaluate()
    // now denies IP literals matching blockedCIDRs up front. Explicit entries
    // in allowedHosts still win (S3 in evaluate's ordering).

    @Test func allowModeDeniesIPLiteralInBlockedCIDR() {
        let filter = DomainFilter(policy: .allow)
        // 127/8, 10/8, 169.254/16 are all in defaultBlockedCIDRs.
        #expect(filter.evaluate(host: "127.0.0.1", port: 22) != .allow)
        #expect(filter.evaluate(host: "10.0.0.5", port: 22) != .allow)
        #expect(filter.evaluate(host: "169.254.169.254", port: 80) != .allow)
        // Public IPs still pass.
        #expect(filter.evaluate(host: "8.8.8.8", port: 443) == .allow)
    }

    @Test func explicitAllowlistOverridesBlockedCIDR() {
        // Putting an IP in allowedHosts is an explicit user opt-in; it must
        // win over default-CIDR blocks (otherwise users couldn't reach a
        // dev service at 127.0.0.1 via a deny-mode policy).
        let filter = DomainFilter(policy: .deny(allowedHosts: ["10.0.0.1"]))
        #expect(filter.evaluate(host: "10.0.0.1", port: 443) == .allow)
        #expect(filter.evaluate(host: "10.0.0.2", port: 443) != .allow)
    }

    // MARK: - Post-DNS resolved-IP check (blockedHosts IPs + CIDRs)

    @Test func resolvedIPMatchesBlockedHostsIPv4() {
        // Hostname-then-resolve: agent connects to evil.example, DNS resolves
        // to 1.2.3.4, which the user blocked by IP literal. The post-DNS check
        // must catch this — upfront evaluate() only sees the hostname.
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["1.2.3.4"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedResolvedIP("1.2.3.4", port: 443))
        #expect(!filter.isBlockedResolvedIP("1.2.3.5", port: 443))
    }

    @Test func resolvedIPMatchesBlockedHostsIPv6() {
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["2001:db8::dead"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedResolvedIP("2001:db8::dead", port: 443))
        #expect(!filter.isBlockedResolvedIP("2001:db8::beef", port: 443))
    }

    @Test func resolvedIPRespectsPortInBlockedHosts() {
        // 1.2.3.4:443 should only block port 443 — port 80 must pass.
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["1.2.3.4:443"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedResolvedIP("1.2.3.4", port: 443))
        #expect(!filter.isBlockedResolvedIP("1.2.3.4", port: 80))
    }

    @Test func resolvedIPMatchesIPv4MappedAcrossFamilies() {
        // blockedHosts entry stored as plain IPv4; resolved peer arrives as
        // ::ffff:10.0.0.1 — matchesHost normalization should bridge the gap.
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["10.0.0.1"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedResolvedIP("::ffff:10.0.0.1", port: 443))
    }

    @Test func resolvedIPStillCatchesCIDR() {
        // The combined check must still fall through to blockedCIDRs.
        let filter = DomainFilter(policy: .deny)
        #expect(filter.isBlockedResolvedIP("10.0.0.1", port: 443))
        #expect(!filter.isBlockedResolvedIP("8.8.8.8", port: 443))
    }

    // MARK: - B-1: explicit allowlist IP overrides post-DNS CIDR check

    @Test func explicitAllowlistIPSurvivesPostDNSCheck() {
        // 10.0.0.1 lies in default-blocked 10/8, but an explicit allowedHosts
        // entry is the user's opt-in — the post-DNS layer must honor it just
        // like upfront evaluate() does. Otherwise the policy's documented
        // behavior is silently broken: evaluate() says allow, then the
        // post-DNS recheck says deny on the same address.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["10.0.0.1"]))
        #expect(!filter.isBlockedResolvedIP("10.0.0.1", port: 443))
        // A different address in the same CIDR is still blocked.
        #expect(filter.isBlockedResolvedIP("10.0.0.2", port: 443))
    }

    @Test func explicitAllowlistIPv6SurvivesPostDNSCheck() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["::1"]))
        #expect(!filter.isBlockedResolvedIP("::1", port: 443))
        // Other addresses in ::1/128 don't exist (it's a /128); use a fc00::
        // address to test that other blocked CIDRs still bite.
        #expect(filter.isBlockedResolvedIP("fc00::1", port: 443))
    }

    @Test func explicitAllowlistRespectsPort() {
        // Allowlist is port-scoped: 10.0.0.1:443 only overrides on port 443.
        let filter = DomainFilter(policy: .deny(allowedHosts: ["10.0.0.1:443"]))
        #expect(!filter.isBlockedResolvedIP("10.0.0.1", port: 443))
        #expect(filter.isBlockedResolvedIP("10.0.0.1", port: 80))
    }

    // MARK: - B-2: trailing-dot host with :port pattern

    @Test func trailingDotHostWithPortBlocksMatchingHost() {
        // "evil.com.:443" was silently inert: parseHostPort split before
        // re-normalization, so the host portion kept its trailing dot and
        // never compared equal to the request's normalized "evil.com".
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["evil.com.:443"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "evil.com", port: 443) != .allow)
        #expect(filter.evaluate(host: "evil.com.", port: 443) != .allow)
    }

    @Test func trailingDotBracketedIPv6PatternMatches() {
        // "[fe80::1.]:443" same shape: bracketed IPv6 with a trailing dot.
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["[fe80::1.]:443"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "fe80::1", port: 443) != .allow)
    }

    // MARK: - B-3: extended default blockedCIDRs

    @Test func defaultsAllowCGNATForTailscale() {
        // CGNAT (100.64.0.0/10, RFC 6598) is deliberately not in
        // defaultBlockedCIDRs — Tailscale's default tailnet lives there and
        // many users expect agents to reach tailscale-exposed dev services.
        // Operators who want it blocked can add it explicitly.
        let filter = DomainFilter(policy: .allow)
        #expect(filter.evaluate(host: "100.64.0.1", port: 443) == .allow)
        #expect(filter.evaluate(host: "100.127.255.254", port: 443) == .allow)
    }

    @Test func defaultBlockedCIDRsCoverThisNetwork() {
        let filter = DomainFilter(policy: .allow)
        // 0.0.0.0/8 — "this network" / source-only, not a valid destination.
        #expect(filter.evaluate(host: "0.0.0.1", port: 443) != .allow)
    }

    @Test func defaultBlockedCIDRsCoverMulticastAndBroadcast() {
        let filter = DomainFilter(policy: .allow)
        // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved (incl. 255.255.255.255).
        #expect(filter.evaluate(host: "224.0.0.1", port: 443) != .allow)
        #expect(filter.evaluate(host: "239.255.255.255", port: 443) != .allow)
        #expect(filter.evaluate(host: "240.0.0.1", port: 443) != .allow)
        #expect(filter.evaluate(host: "255.255.255.255", port: 443) != .allow)
    }

    @Test func defaultBlockedCIDRsCoverIPv6Multicast() {
        let filter = DomainFilter(policy: .allow)
        // ff00::/8 — IPv6 multicast (RFC 4291).
        #expect(filter.evaluate(host: "ff02::1", port: 443) != .allow)
    }

    // MARK: - B-5: IPv6 zone-IDs stripped at evaluate time

    @Test func ipv6ZoneIDStrippedBeforeCIDRCheck() {
        // fe80::1%eth0 with the zone ID intact would slip past the
        // pre-connect CIDR check (inet_pton rejects zoned form, so the
        // check returns false and proceeds to dial). The post-DNS layer
        // catches it eventually, but the SYN reveals open/closed/RST.
        let filter = DomainFilter(policy: .allow)
        #expect(filter.evaluate(host: "fe80::1%eth0", port: 443) != .allow)
    }

    @Test func ipv6ZoneIDStrippedFromAllowlistMatch() {
        // A zoned form in the allowlist also strips at parse time so it
        // matches the canonical form (and vice versa).
        let filter = DomainFilter(policy: .deny(allowedHosts: ["fe80::1%eth0"]))
        #expect(filter.evaluate(host: "fe80::1", port: 443) == .allow)
    }
}

// MARK: - Adversarial: IPv4-mapped IPv6 cross-family matching

struct AdversarialDomainFilterTests {
    // Bug #2: matchesHost has separate IPv4 and IPv6 code paths with no
    // cross-family matching. An IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    // in the host lists is stored as IPv6 binary, but a plain IPv4 host
    // is parsed as IPv4 binary. They never compare against each other.

    @Test func ipv4MappedIPv6InBlocklistShouldBlockPlainIPv4() {
        // ::ffff:10.0.0.1 and 10.0.0.1 are the same address (RFC 4291 §2.5.5.2).
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["::ffff:10.0.0.1"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        let decision = filter.evaluate(host: "10.0.0.1", port: 443)
        #expect(
            decision != .allow,
            "IPv4-mapped IPv6 '::ffff:10.0.0.1' in blocklist should block plain IPv4 '10.0.0.1'")
    }

    /// Bug #3: Reverse direction of bug #2.
    @Test func plainIPv4InBlocklistShouldBlockIPv4MappedIPv6() {
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["10.0.0.1"],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        let decision = filter.evaluate(host: "::ffff:10.0.0.1", port: 443)
        #expect(
            decision != .allow,
            "Plain IPv4 '10.0.0.1' in blocklist should block IPv4-mapped IPv6 '::ffff:10.0.0.1'")
    }

    @Test func ipv4MappedIPv6InAllowlistShouldAllowPlainIPv4() {
        // In deny mode, the allowlist should recognize IPv4-mapped addresses.
        let policy = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["::ffff:93.184.216.34"],
            blockedHosts: [],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        let decision = filter.evaluate(host: "93.184.216.34", port: 443)
        #expect(
            decision == .allow,
            "IPv4-mapped IPv6 in allowlist should allow the equivalent plain IPv4 address")
    }

    @Test func plainIPv4InAllowlistShouldAllowIPv4MappedIPv6() {
        let policy = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["93.184.216.34"],
            blockedHosts: [],
            blockedCIDRs: []
        )
        let filter = DomainFilter(policy: policy)
        let decision = filter.evaluate(host: "::ffff:93.184.216.34", port: 443)
        #expect(
            decision == .allow,
            "Plain IPv4 in allowlist should allow IPv4-mapped IPv6 equivalent")
    }
}

// MARK: - Pattern normalization regressions

struct DomainFilterPatternNormalizationBugs {
    // evaluate() strips trailing dots from the incoming host, but patterns in
    // allowedHosts/blockedHosts are not normalized. In DNS, "example.com." and
    // "example.com" are the same name, so patterns should be normalized too.

    @Test func allowlistPatternTrailingDotNotStripped() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com."]))
        #expect(
            filter.evaluate(host: "example.com", port: 443) == .allow,
            "Pattern 'example.com.' should match host 'example.com'")
    }

    @Test func blocklistPatternTrailingDotNotStripped() {
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["evil.com."], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(
            filter.evaluate(host: "evil.com", port: 443) != .allow,
            "Blocked pattern 'evil.com.' should block 'evil.com'")
    }

    @Test func wildcardAllowlistPatternTrailingDotNotStripped() {
        // "*.example.com." → suffix is ".example.com." which won't match
        // "sub.example.com" because the host doesn't end with ".example.com."
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com."]))
        #expect(
            filter.evaluate(host: "sub.example.com", port: 443) == .allow,
            "Wildcard pattern '*.example.com.' should match subdomains")
    }

    @Test func wildcardBlocklistPatternTrailingDotNotStripped() {
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: ["*.evil.com."], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(
            filter.evaluate(host: "sub.evil.com", port: 443) != .allow,
            "Wildcard blocked pattern '*.evil.com.' should block subdomains")
    }
}

// MARK: - Whitespace and multi-dot regressions

struct DomainFilterWhitespaceBugs {
    @Test func patternWithLeadingWhitespaceDoesNotMatch() {
        // Leading whitespace in a pattern prevents exact match because
        // " evil.com" != "evil.com". Patterns should be trimmed.
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [],
            blockedHosts: [" evil.com"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(
            filter.evaluate(host: "evil.com", port: 443) != .allow,
            "Pattern with leading whitespace should still match the host")
    }

    @Test func cidrWithLeadingWhitespaceFailsToBlock() throws {
        // Leading whitespace makes inet_pton fail, silently disabling the CIDR rule.
        let policy = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR(" 10.0.0.0/8"))])
        let filter = DomainFilter(policy: policy)
        #expect(
            filter.isBlockedCIDR("10.0.0.1"),
            "Leading whitespace in CIDR should not disable the block rule")
    }

    @Test func multipleTrailingDotsNotFullyStripped() {
        // The code strips exactly one trailing dot. A host with two trailing dots
        // ("example.com..") becomes "example.com." after stripping, which doesn't
        // match the pattern "example.com".
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com"]))
        #expect(
            filter.evaluate(host: "example.com..", port: 443) == .allow,
            "All trailing dots should be stripped to match the base domain")
    }
}
