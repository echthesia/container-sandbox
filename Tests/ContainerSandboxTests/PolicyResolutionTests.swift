import Foundation
@testable import sandbox
import Testing

struct PolicyResolutionTests {
    // MARK: - NetworkPolicyOptions.resolve

    @Test func noOverridesReturnsTemplateDefaults() throws {
        let options = try NetworkPolicyOptions.parse([])
        let policy = options.resolve(template: ClaudeTemplate())
        // ClaudeTemplate defaults to deny with *.claude.ai + default allowed hosts
        #expect(policy.direction == .deny)
        #expect(policy.allowedHosts.contains("*.claude.ai"))
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
    }

    @Test func directionOverridePreservesTemplateHosts() throws {
        let options = try NetworkPolicyOptions.parse(["--policy", "allow"])
        let policy = options.resolve(template: ClaudeTemplate())
        #expect(policy.direction == .allow)
        // Template hosts are preserved when only direction changes
        #expect(policy.allowedHosts.contains("*.claude.ai"))
        #expect(policy.allowedHosts.contains("*.anthropic.com"))
    }

    @Test func allowHostAppendsToTemplateList() throws {
        let options = try NetworkPolicyOptions.parse(["--allow-host", "*.github.com"])
        let policy = options.resolve(template: ClaudeTemplate())
        // Original template hosts still present
        #expect(policy.allowedHosts.contains("*.claude.ai"))
        // New host appended
        #expect(policy.allowedHosts.contains("*.github.com"))
    }

    @Test func blockHostAppendsToTemplateList() throws {
        let options = try NetworkPolicyOptions.parse(["--block-host", "evil.com"])
        let policy = options.resolve(template: ClaudeTemplate())
        #expect(policy.blockedHosts.contains("evil.com"))
    }

    @Test func multipleHostsAppended() throws {
        let options = try NetworkPolicyOptions.parse([
            "--allow-host", "a.com",
            "--allow-host", "b.com",
            "--block-host", "c.com",
            "--block-host", "d.com",
        ])
        let policy = options.resolve(template: ShellTemplate())
        #expect(policy.allowedHosts.contains("a.com"))
        #expect(policy.allowedHosts.contains("b.com"))
        #expect(policy.blockedHosts.contains("c.com"))
        #expect(policy.blockedHosts.contains("d.com"))
    }

    @Test func shellTemplateDefaultsToAllow() throws {
        let options = try NetworkPolicyOptions.parse([])
        let policy = options.resolve(template: ShellTemplate())
        #expect(policy.direction == .allow)
    }

    @Test func directionAndHostsCombined() throws {
        let options = try NetworkPolicyOptions.parse([
            "--policy", "deny",
            "--allow-host", "*.github.com",
        ])
        let policy = options.resolve(template: ShellTemplate())
        #expect(policy.direction == .deny)
        #expect(policy.allowedHosts.contains("*.github.com"))
    }

    @Test func blockedCIDRsUntouchedByResolve() throws {
        let options = try NetworkPolicyOptions.parse(["--allow-host", "foo.com"])
        let policy = options.resolve(template: ClaudeTemplate())
        // CIDRs come from template defaults, resolve doesn't modify them
        #expect(policy.blockedCIDRs == NetworkPolicy.defaultBlockedCIDRs)
    }
}
