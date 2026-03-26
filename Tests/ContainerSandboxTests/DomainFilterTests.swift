@testable import sandbox
import Testing

@Suite("DomainFilter")
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
}
