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
