import Foundation
@testable import sandbox
import Testing

@Suite("NetworkPolicy")
struct NetworkPolicyTests {

    @Test func fullPolicyDefaults() {
        let policy = NetworkPolicy.full
        #expect(policy.mode == .full)
        #expect(policy.allowedHosts.isEmpty)
        #expect(policy.blockedHosts.isEmpty)
    }

    @Test func nonePolicyDefaults() {
        let policy = NetworkPolicy.none
        #expect(policy.mode == .none)
    }

    @Test func filteredWithHosts() {
        let policy = NetworkPolicy.filtered(allowedHosts: ["*.anthropic.com", "*.claude.ai"])
        #expect(policy.mode == .filtered)
        #expect(policy.direction == .deny)
        #expect(policy.allowedHosts == ["*.anthropic.com", "*.claude.ai"])
        #expect(policy.blockedCIDRs == NetworkPolicy.defaultBlockedCIDRs)
    }

    @Test func allowedHostsLabel() {
        let policy = NetworkPolicy.filtered(allowedHosts: ["a.com", "b.com"])
        #expect(policy.allowedHostsLabel == "a.com,b.com")
    }

    @Test func emptyAllowedHostsLabel() {
        let policy = NetworkPolicy.full
        #expect(policy.allowedHostsLabel == "")
    }

    @Test func codableRoundTrip() throws {
        let original = NetworkPolicy.filtered(
            allowedHosts: ["*.anthropic.com"],
            blockedHosts: ["evil.com"],
            blockedCIDRs: ["10.0.0.0/8"]
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        #expect(decoded == original)
    }

    @Test func resolveNetworkPolicyDefaultsToTemplate() {
        let template = ClaudeTemplate()
        let policy = RunCommand.resolveNetworkPolicy(
            template: template, network: nil, allowHost: [], blockHost: []
        )
        #expect(policy.mode == .filtered)
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
    }

    @Test func resolveNetworkPolicyOverridesMode() {
        let template = ClaudeTemplate()
        let policy = RunCommand.resolveNetworkPolicy(
            template: template, network: "full", allowHost: [], blockHost: []
        )
        #expect(policy.mode == .full)
    }

    @Test func resolveNetworkPolicyAppendsHosts() {
        let template = ClaudeTemplate()
        let policy = RunCommand.resolveNetworkPolicy(
            template: template, network: nil, allowHost: ["*.github.com"], blockHost: ["evil.com"]
        )
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
        #expect(policy.allowedHosts.contains("*.github.com"))
        #expect(policy.blockedHosts.contains("evil.com"))
    }
}
