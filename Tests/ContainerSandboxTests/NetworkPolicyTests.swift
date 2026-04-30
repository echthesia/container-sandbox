import Foundation
import Testing

@testable import sandbox

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
        let original = try NetworkPolicy.deny(
            allowedHosts: ["*.anthropic.com"],
            blockedHosts: ["evil.com"],
            blockedCIDRs: [#require(NormalizedCIDR("10.0.0.0/8"))]
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        #expect(decoded == original)
    }

    @Test func codableRoundTripWithSpecialCharacters() throws {
        let original = try NetworkPolicy(
            direction: .deny,
            allowedHosts: ["*.example.com", "api.test-host.co.uk:443"],
            blockedHosts: ["evil-site.com"],
            blockedCIDRs: [#require(NormalizedCIDR("::1/128")), #require(NormalizedCIDR("fc00::/7"))]
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

    @Test func cidrLeadingZeroPrefixNormalized() throws {
        // "10.0.0.0/8" and "10.0.0.0/08" are semantically the same CIDR
        let a = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("10.0.0.0/8"))])
        let b = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("10.0.0.0/08"))])
        #expect(a == b)
    }

    @Test func differentDirectionsNotEqual() {
        let a = NetworkPolicy(direction: .allow, allowedHosts: [], blockedHosts: [], blockedCIDRs: [])
        let b = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [], blockedCIDRs: [])
        #expect(a != b)
    }

    @Test func cidrHostBitsMasked() throws {
        // 10.0.0.1/8 and 10.0.0.0/8 represent the same CIDR block
        let a = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("10.0.0.1/8"))])
        let b = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("10.0.0.0/8"))])
        #expect(a == b)
    }

    @Test func cidrHostBitsMaskedIPv6() throws {
        // fc00::1/7 and fc00::/7 represent the same CIDR block
        let a = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("fc00::1/7"))])
        let b = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("fc00::/7"))])
        #expect(a == b)
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

// MARK: - Adversarial: equality normalization gaps

struct AdversarialNetworkPolicyTests {
    // Bug #4: normalizedSet only lowercases hosts, doesn't strip trailing dots.
    // DomainFilter.parseHosts normalizes trailing dots, so "example.com." and
    // "example.com" produce identical filter behavior. But NetworkPolicy equality
    // treats them as different.

    @Test func equalityWithTrailingDotInAllowedHosts() {
        let a = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["example.com."],
            blockedHosts: [],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let b = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["example.com"],
            blockedHosts: [],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        #expect(
            a == b,
            "Trailing dot should not affect host equality — 'example.com.' and 'example.com' are the same DNS name")
    }

    @Test func equalityWithTrailingDotInBlockedHosts() {
        let a = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["evil.com."],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let b = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: ["evil.com"],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        #expect(
            a == b,
            "Trailing dot in blockedHosts should not break equality")
    }

    /// Bug #5: normalizedSet doesn't trim whitespace.
    @Test func equalityWithWhitespaceInHosts() {
        let a = NetworkPolicy(
            direction: .deny,
            allowedHosts: [" example.com"],
            blockedHosts: [],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let b = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["example.com"],
            blockedHosts: [],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        #expect(
            a == b,
            "Leading whitespace should not affect host equality — DomainFilter.parseHosts trims whitespace")
    }

    @Test func equalityWithTrailingWhitespaceInHosts() {
        let a = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["example.com "],
            blockedHosts: [],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let b = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["example.com"],
            blockedHosts: [],
            blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        #expect(
            a == b,
            "Trailing whitespace should not affect host equality")
    }

    // Bug #6: NormalizedCIDR fails to parse CIDRs with whitespace because
    // inet_pton rejects leading/trailing whitespace.

    @Test func normalizedCIDRWithLeadingWhitespace() {
        let cidr = NormalizedCIDR(" 10.0.0.0/8")
        #expect(
            cidr != nil,
            "NormalizedCIDR should handle leading whitespace — inet_pton rejects it, causing silent CIDR drop")
    }

    @Test func normalizedCIDRWithTrailingWhitespace() {
        let cidr = NormalizedCIDR("10.0.0.0/8 ")
        #expect(
            cidr != nil,
            "NormalizedCIDR should handle trailing whitespace")
    }

    @Test func normalizedCIDRWithWhitespaceIPv6() {
        let cidr = NormalizedCIDR(" fc00::/7")
        #expect(
            cidr != nil,
            "NormalizedCIDR should handle whitespace in IPv6 CIDRs")
    }

    @Test func policyEqualityWithWhitespaceCIDR() throws {
        // A CIDR with whitespace is silently dropped by NormalizedCIDR,
        // making two semantically identical policies unequal.
        let a = try NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR(" 10.0.0.0/8"))]
        )
        let b = try NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("10.0.0.0/8"))]
        )
        #expect(
            a == b,
            "Whitespace in CIDR should not break policy equality — the range is identical")
    }

    /// Bug #10: init(from decoder:) rejects whitespace CIDRs via NormalizedCIDR
    /// validation, even though isBlockedCIDR handles whitespace at runtime.
    @Test func decodePolicyWithWhitespaceCIDR() throws {
        let json = """
            {
                "direction": "deny",
                "allowedHosts": [],
                "blockedHosts": [],
                "blockedCIDRs": [" 10.0.0.0/8"]
            }
            """
        let data = Data(json.utf8)
        // This should succeed — the CIDR is valid, just has whitespace.
        // But NormalizedCIDR(" 10.0.0.0/8") returns nil, causing decode to throw.
        #expect(throws: Never.self) {
            _ = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        }
    }
}

// MARK: - CIDR equality regressions

struct NetworkPolicyEqualityBugs {
    @Test func cidrCaseInsensitiveEquality() throws {
        // normalizedCIDRSet doesn't lowercase the address portion,
        // so "FC00::/7" and "fc00::/7" are treated as different CIDRs
        // despite representing the same network range.
        let a = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("FC00::/7"))])
        let b = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("fc00::/7"))])
        #expect(a == b, "CIDRs should be compared case-insensitively for hex digits")
    }

    @Test func ipv6NormalizationInCidrEquality() throws {
        // Two string representations of the same IPv6 address are not
        // recognized as equal because normalizedCIDRSet uses string comparison.
        let a = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("::1/128"))])
        let b = try NetworkPolicy(
            direction: .deny, allowedHosts: [], blockedHosts: [],
            blockedCIDRs: [#require(NormalizedCIDR("0000:0000:0000:0000:0000:0000:0000:0001/128"))])
        #expect(a == b, "Equivalent IPv6 addresses should be equal in CIDR comparison")
    }
}

// MARK: - JSON roundtrip

struct NetworkPolicyRoundtripTests {
    /// NetworkPolicy JSON roundtrip should preserve equality.
    @Test func networkPolicyJsonRoundtrip() throws {
        let policies: [NetworkPolicy] = try [
            .allow,
            .deny,
            .deny(allowedHosts: ["example.com", "*.test.org:8080"]),
            NetworkPolicy(
                direction: .allow, allowedHosts: ["MIXED.Case.Host"],
                blockedHosts: ["blocked.example.com"],
                blockedCIDRs: [#require(NormalizedCIDR("10.0.0.0/8"))]),
        ]
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        for policy in policies {
            let data = try encoder.encode(policy)
            let decoded = try decoder.decode(NetworkPolicy.self, from: data)
            #expect(
                policy == decoded,
                "NetworkPolicy should survive JSON roundtrip")
        }
    }
}
