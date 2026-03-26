import Foundation
@testable import sandbox
import Testing

@Suite("NetworkPolicy")
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
        let template = ClaudeTemplate()
        let policy = try RunCommand.resolveNetworkPolicy(
            template: template, policy: nil, allowHost: [], blockHost: []
        )
        #expect(policy.direction == .deny)
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
    }

    @Test func resolveNetworkPolicyOverridesDirection() throws {
        let template = ClaudeTemplate()
        let policy = try RunCommand.resolveNetworkPolicy(
            template: template, policy: "allow", allowHost: [], blockHost: []
        )
        #expect(policy.direction == .allow)
    }

    @Test func resolveNetworkPolicyAppendsHosts() throws {
        let template = ClaudeTemplate()
        let policy = try RunCommand.resolveNetworkPolicy(
            template: template, policy: nil, allowHost: ["*.github.com"], blockHost: ["evil.com"]
        )
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
        #expect(policy.allowedHosts.contains("*.github.com"))
        #expect(policy.blockedHosts.contains("evil.com"))
    }

    @Test func resolveNetworkPolicyRejectsInvalidDirection() {
        #expect(throws: (any Error).self) {
            try RunCommand.resolveNetworkPolicy(
                template: ClaudeTemplate(), policy: "yolo", allowHost: [], blockHost: []
            )
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
}
