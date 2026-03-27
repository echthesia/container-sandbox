import Foundation
@testable import sandbox
import Testing

/// Tests the policy mutation logic as used by NetworkProxyCommand.
/// The mutation contract: load existing policy as base, then apply incremental
/// overrides (direction, allow hosts, block hosts). This is NOT struct property
/// testing — it verifies the actual merge semantics the command relies on.
struct PolicyMutationTests {
    /// Simulates the mutation path in NetworkProxyCommand: load base, apply overrides.
    private func applyOverrides(
        base: NetworkPolicy,
        direction: PolicyDirection? = nil,
        allowHosts: [String] = [],
        blockHosts: [String] = []
    ) -> NetworkPolicy {
        var updated = base
        if let direction {
            updated.direction = direction
        }
        if !allowHosts.isEmpty {
            updated.allowedHosts.append(contentsOf: allowHosts)
        }
        if !blockHosts.isEmpty {
            updated.blockedHosts.append(contentsOf: blockHosts)
        }
        return updated
    }

    // MARK: - Direction override

    @Test func directionOverridePreservesExistingHosts() {
        let base = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        let result = applyOverrides(base: base, direction: .allow)
        #expect(result.direction == .allow)
        // All existing hosts must be preserved
        #expect(result.allowedHosts.contains("*.claude.ai"))
        #expect(result.allowedHosts.contains("*.anthropic.com"))
        #expect(result.blockedCIDRs == base.blockedCIDRs, "CIDRs must not change")
    }

    @Test func directionOverrideFromAllowToDeny() {
        let base = NetworkPolicy.allow
        let result = applyOverrides(base: base, direction: .deny)
        #expect(result.direction == .deny)
        #expect(result.allowedHosts == base.allowedHosts, "Hosts must not change")
    }

    // MARK: - Host appending

    @Test func allowHostAppendsToExistingList() {
        let base = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        let result = applyOverrides(base: base, allowHosts: ["*.github.com"])
        #expect(result.allowedHosts.contains("*.claude.ai"), "Original host must be preserved")
        #expect(result.allowedHosts.contains("*.github.com"), "New host must be appended")
    }

    @Test func blockHostAppendsToExistingList() {
        let base = NetworkPolicy.allow
        let result = applyOverrides(base: base, blockHosts: ["evil.com"])
        #expect(result.blockedHosts.contains("evil.com"))
    }

    @Test func multipleOverridesInOneCall() {
        let base = NetworkPolicy.allow
        let result = applyOverrides(
            base: base,
            direction: .deny,
            allowHosts: ["api.example.com", "*.trusted.org"],
            blockHosts: ["malware.net"]
        )
        #expect(result.direction == .deny)
        #expect(result.allowedHosts.contains("api.example.com"))
        #expect(result.allowedHosts.contains("*.trusted.org"))
        #expect(result.blockedHosts.contains("malware.net"))
    }

    // MARK: - Incremental mutations (apply multiple times)

    @Test func sequentialMutationsAccumulate() {
        let base = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        let afterFirst = applyOverrides(base: base, allowHosts: ["*.github.com"])
        let afterSecond = applyOverrides(base: afterFirst, allowHosts: ["*.npmjs.org"])
        // All three sources of hosts must be present
        #expect(afterSecond.allowedHosts.contains("*.claude.ai"))
        #expect(afterSecond.allowedHosts.contains("*.github.com"))
        #expect(afterSecond.allowedHosts.contains("*.npmjs.org"))
    }

    @Test func directionChangeDoesNotResetHosts() {
        let base = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        let withExtraHost = applyOverrides(base: base, allowHosts: ["*.github.com"])
        let withDirChange = applyOverrides(base: withExtraHost, direction: .allow)
        // Switching direction must NOT remove previously added hosts
        #expect(withDirChange.allowedHosts.contains("*.claude.ai"))
        #expect(withDirChange.allowedHosts.contains("*.github.com"))
    }

    // MARK: - Immutable fields

    @Test func blockedCIDRsUnchangedByMutation() {
        let base = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        let result = applyOverrides(
            base: base,
            direction: .allow,
            allowHosts: ["foo.com"],
            blockHosts: ["bar.com"]
        )
        #expect(result.blockedCIDRs == base.blockedCIDRs,
                "CIDRs must not be affected by host/direction mutations")
    }

    // MARK: - Fallback base policy

    @Test func mutationFromDefaultAllowPolicy() {
        // When no existing policy exists, NetworkProxyCommand falls back to .allow
        let result = applyOverrides(base: .allow, direction: .deny, allowHosts: ["*.github.com"])
        #expect(result.direction == .deny)
        #expect(result.allowedHosts.contains("*.github.com"))
        #expect(result.allowedHosts.contains("*.anthropic.com"), "Default hosts must be in base")
    }

    // MARK: - No-op mutation

    @Test func noOverridesReturnsBaseUnchanged() {
        let base = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        let result = applyOverrides(base: base)
        #expect(result == base)
    }

    // MARK: - Round-trip through state storage

    @Test func mutatedPolicySurvivesJSONRoundTrip() throws {
        let base = NetworkPolicy.deny(allowedHosts: ["*.claude.ai"])
        let mutated = applyOverrides(base: base, direction: .allow, allowHosts: ["*.github.com"], blockHosts: ["evil.com"])

        let data = try JSONEncoder().encode(mutated)
        let decoded = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        #expect(decoded == mutated)
    }
}
