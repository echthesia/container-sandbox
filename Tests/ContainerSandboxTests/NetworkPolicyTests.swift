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

    @Test func allowedHostsLabel() {
        let policy = NetworkPolicy.deny(allowedHosts: ["a.com", "b.com"])
        #expect(policy.allowedHostsLabel.contains("a.com"))
        #expect(policy.allowedHostsLabel.contains("b.com"))
    }

    @Test func emptyBlockedHostsLabel() {
        let policy = NetworkPolicy.allow
        #expect(policy.blockedHostsLabel == "")
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

    @Test func resolveNetworkPolicyDefaultsToTemplate() throws {
        let options = try NetworkPolicyOptions.parse([])
        let policy = options.resolve(template: ClaudeTemplate())
        #expect(policy.direction == .deny)
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
    }

    @Test func resolveNetworkPolicyOverridesDirection() throws {
        let options = try NetworkPolicyOptions.parse(["--policy", "allow"])
        let policy = options.resolve(template: ClaudeTemplate())
        #expect(policy.direction == .allow)
        // Changing direction preserves template's allowed hosts
        #expect(policy.allowedHosts.contains("*.claude.ai"))
    }

    @Test func resolveNetworkPolicyAppendsHosts() throws {
        let options = try NetworkPolicyOptions.parse([
            "--allow-host", "*.github.com", "--block-host", "evil.com",
        ])
        let policy = options.resolve(template: ClaudeTemplate())
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
        #expect(policy.allowedHosts.contains("*.github.com"))
        #expect(policy.blockedHosts.contains("evil.com"))
    }

    @Test func resolveNetworkPolicyRejectsInvalidDirection() {
        #expect(throws: (any Error).self) {
            try NetworkPolicyOptions.parse(["--policy", "yolo"])
        }
    }

    @Test func labelRoundTrip() {
        // Encode a policy to labels, then decode via fromLabels() — the real code path.
        let original = NetworkPolicy.deny(
            allowedHosts: ["*.github.com", "api.example.com:443"],
            blockedHosts: ["evil.com"],
            blockedCIDRs: ["10.0.0.0/8", "172.16.0.0/12"]
        )

        // Simulate label encoding (same as SandboxManager.ensureSandboxExists).
        let labels: [String: String] = [
            SandboxLabels.direction: original.direction.rawValue,
            SandboxLabels.allowedHosts: original.allowedHostsLabel,
            SandboxLabels.blockedHosts: original.blockedHostsLabel,
            SandboxLabels.blockedCIDRs: original.blockedCIDRsLabel,
        ]

        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded == original)
    }

    // MARK: - Label round-trip contracts

    @Test func labelRoundTripAllowPolicy() {
        let original = NetworkPolicy.allow
        let labels = policyToLabels(original)
        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded == original)
    }

    @Test func labelRoundTripDenyPolicy() {
        let original = NetworkPolicy.deny
        let labels = policyToLabels(original)
        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded == original)
    }

    @Test func labelRoundTripEmptyHosts() {
        let original = NetworkPolicy(
            direction: .deny,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )
        let labels = policyToLabels(original)
        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded == original)
    }

    @Test func labelRoundTripSpecialCharactersInHosts() {
        let original = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["*.example.com", "api.test-host.co.uk:443"],
            blockedHosts: ["evil-site.com"],
            blockedCIDRs: ["::1/128", "fc00::/7"]
        )
        let labels = policyToLabels(original)
        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded == original)
    }

    @Test func fromLabelsMissingDirectionReturnsNil() {
        // No direction label at all → nil (not crash)
        let labels: [String: String] = [
            SandboxLabels.allowedHosts: "a.com",
            SandboxLabels.blockedHosts: "",
        ]
        #expect(NetworkPolicy.fromLabels(labels) == nil)
    }

    @Test func fromLabelsInvalidDirectionReturnsNil() {
        let labels: [String: String] = [
            SandboxLabels.direction: "yolo",
        ]
        #expect(NetworkPolicy.fromLabels(labels) == nil)
    }

    @Test func fromLabelsAbsentCIDRsUsesDefaults() {
        // Absent blockedCIDRs label → use defaults
        let labels: [String: String] = [
            SandboxLabels.direction: "allow",
            SandboxLabels.allowedHosts: "",
            SandboxLabels.blockedHosts: "",
            // No blockedCIDRs key
        ]
        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded?.blockedCIDRs == NetworkPolicy.defaultBlockedCIDRs)
    }

    @Test func fromLabelsEmptyCIDRsMeansIntentionallyEmpty() {
        // Present-but-empty blockedCIDRs → intentionally empty (not defaults)
        let labels: [String: String] = [
            SandboxLabels.direction: "allow",
            SandboxLabels.allowedHosts: "",
            SandboxLabels.blockedHosts: "",
            SandboxLabels.blockedCIDRs: "",
        ]
        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded?.blockedCIDRs.isEmpty == true)
    }

    @Test func fromLabelsExtraUnknownLabelsIgnored() {
        var labels = policyToLabels(NetworkPolicy.allow)
        labels["some.unknown.label"] = "whatever"
        labels["sandbox.future-feature"] = "value"
        let decoded = NetworkPolicy.fromLabels(labels)
        #expect(decoded == NetworkPolicy.allow)
    }

    // MARK: - Adversarial: equality edge cases

    @Test func equalityIgnoresDuplicateHosts() {
        let a = NetworkPolicy(direction: .deny, allowedHosts: ["a.com", "a.com"], blockedHosts: [], blockedCIDRs: [])
        let b = NetworkPolicy(direction: .deny, allowedHosts: ["a.com"], blockedHosts: [], blockedCIDRs: [])
        // Set-based comparison removes duplicates — these are equal
        #expect(a == b)
    }

    @Test func duplicateHostsLabelRoundTripBreaksEquality() throws {
        // ["a.com", "a.com"] serializes as "a.com,a.com" but deserializes as ["a.com", "a.com"]
        // Then equality compares as sets, so roundtrip preserves equality.
        // But the raw label string differs from ["a.com"] → "a.com"
        let original = NetworkPolicy(
            direction: .deny, allowedHosts: ["a.com", "a.com"],
            blockedHosts: [], blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let labels = policyToLabels(original)
        let decoded = try #require(NetworkPolicy.fromLabels(labels))
        // Semantic equality holds despite different serialized forms
        #expect(decoded == original)
    }

    @Test func caseVariationsInLabelRoundTrip() throws {
        let original = NetworkPolicy(
            direction: .deny, allowedHosts: ["A.COM", "B.com"],
            blockedHosts: [], blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let labels = policyToLabels(original)
        let decoded = try #require(NetworkPolicy.fromLabels(labels))
        // Case is preserved in serialization, and equality is case-insensitive
        #expect(decoded == original)
    }

    @Test func whitespaceInHostPreservedThroughRoundTrip() throws {
        // Whitespace in hostnames is not trimmed — preserved through serialization
        let original = NetworkPolicy(
            direction: .deny, allowedHosts: [" a.com "],
            blockedHosts: [], blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs
        )
        let labels = policyToLabels(original)
        let decoded = try #require(NetworkPolicy.fromLabels(labels))
        // The space is preserved — " a.com " != "a.com" in the filter
        #expect(decoded.allowedHosts.contains(" a.com "))
    }

    @Test func fromLabelsWithWhitespaceAroundCommas() throws {
        // "a.com , b.com" — split on "," preserves whitespace in entries
        let labels: [String: String] = [
            SandboxLabels.direction: "deny",
            SandboxLabels.allowedHosts: "a.com , b.com",
            SandboxLabels.blockedHosts: "",
            SandboxLabels.blockedCIDRs: NetworkPolicy.defaultBlockedCIDRs.joined(separator: ","),
        ]
        let decoded = try #require(NetworkPolicy.fromLabels(labels))
        // " b.com" has a leading space — not trimmed
        #expect(decoded.allowedHosts.contains(" b.com"))
    }

    // MARK: - Adversarial: CIDR notation equivalence

    @Test func cidrLeadingZeroPrefixBreaksEquality() {
        // "10.0.0.0/8" and "10.0.0.0/08" are semantically the same CIDR
        // but Set comparison treats them as different strings
        let a = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["10.0.0.0/8"])
        let b = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["10.0.0.0/08"])
        // These should be equal (same CIDR) but currently aren't (string comparison)
        #expect(a == b)
    }

    // MARK: - Helpers

    private func policyToLabels(_ policy: NetworkPolicy) -> [String: String] {
        [
            SandboxLabels.direction: policy.direction.rawValue,
            SandboxLabels.allowedHosts: policy.allowedHostsLabel,
            SandboxLabels.blockedHosts: policy.blockedHostsLabel,
            SandboxLabels.blockedCIDRs: policy.blockedCIDRsLabel,
        ]
    }
}
