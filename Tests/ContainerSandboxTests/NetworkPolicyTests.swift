import Foundation
@testable import sandbox
import Testing

struct NetworkPolicyTests {
    @Test func allowPolicyDefaults() {
        let policy = NetworkPolicy.allow
        #expect(policy.direction == .allow)
        #expect(policy.allowedHosts == NetworkPolicy.defaultAllowedHosts)
        #expect(policy.blockedHosts.isEmpty)
        #expect(policy.blockedCIDRs == NetworkPolicy.defaultBlockedCIDRs)
    }

    @Test func denyPolicyDefaults() {
        let policy = NetworkPolicy.deny
        #expect(policy.direction == .deny)
        #expect(policy.allowedHosts == NetworkPolicy.defaultAllowedHosts)
    }

    @Test func denyWithHosts() {
        let policy = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        #expect(policy.direction == .deny)
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
        #expect(policy.allowedHosts.contains("*.claude.ai"))
        #expect(policy.blockedCIDRs == NetworkPolicy.defaultBlockedCIDRs)
    }

    @Test func codableRoundTrip() throws {
        let original = NetworkPolicy.deny(
            allowedHosts: ["*.anthropic.com"],
            blockedHosts: ["evil.com"],
            blockedCIDRs: ["10.0.0.0/8"]
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        #expect(decoded == original)
    }

    @Test func codableRoundTripWithSpecialCharacters() throws {
        let original = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["*.example.com", "api.test-host.co.uk:443"],
            blockedHosts: ["evil-site.com"],
            blockedCIDRs: ["::1/128", "fc00::/7"]
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        #expect(decoded == original)
    }

    @Test func codableRoundTripEmptyHosts() throws {
        let original = NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        #expect(decoded == original)
    }

    // MARK: - Equality edge cases

    @Test func equalityIgnoresDuplicateHosts() {
        let a = NetworkPolicy(direction: .deny, allowedHosts: ["a.com", "a.com"], blockedHosts: [], blockedCIDRs: [])
        let b = NetworkPolicy(direction: .deny, allowedHosts: ["a.com"], blockedHosts: [], blockedCIDRs: [])
        #expect(a == b)
    }

    @Test func equalityIsCaseInsensitive() {
        let a = NetworkPolicy(direction: .deny, allowedHosts: ["A.COM"], blockedHosts: [], blockedCIDRs: [])
        let b = NetworkPolicy(direction: .deny, allowedHosts: ["a.com"], blockedHosts: [], blockedCIDRs: [])
        #expect(a == b)
    }

    @Test func equalityIsOrderIndependent() {
        let a = NetworkPolicy(direction: .deny, allowedHosts: ["a.com", "b.com"], blockedHosts: [], blockedCIDRs: [])
        let b = NetworkPolicy(direction: .deny, allowedHosts: ["b.com", "a.com"], blockedHosts: [], blockedCIDRs: [])
        #expect(a == b)
    }

    @Test func cidrLeadingZeroPrefixNormalized() {
        // "10.0.0.0/8" and "10.0.0.0/08" are semantically the same CIDR
        let a = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["10.0.0.0/8"])
        let b = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["10.0.0.0/08"])
        #expect(a == b)
    }

    @Test func differentDirectionsNotEqual() {
        let a = NetworkPolicy(direction: .allow, allowedHosts: [], blockedHosts: [], blockedCIDRs: [])
        let b = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [], blockedCIDRs: [])
        #expect(a != b)
    }

    @Test func differentHostsNotEqual() {
        let a = NetworkPolicy(direction: .deny, allowedHosts: ["a.com"], blockedHosts: [], blockedCIDRs: [])
        let b = NetworkPolicy(direction: .deny, allowedHosts: ["b.com"], blockedHosts: [], blockedCIDRs: [])
        #expect(a != b)
    }

    @Test func codablePreservesCase() throws {
        // Case is preserved through JSON (equality is insensitive, but storage is not lossy)
        let original = NetworkPolicy(
            direction: .deny, allowedHosts: ["A.COM", "B.com"],
            blockedHosts: [], blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        #expect(decoded.allowedHosts == ["A.COM", "B.com"], "JSON should preserve exact case")
        #expect(decoded == original, "Equality should still hold")
    }
}
