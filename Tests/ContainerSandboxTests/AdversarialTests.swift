import ContainerResource
import ContainerizationOCI
import Foundation
import Testing

@testable import sandbox

// =============================================================================
// Adversarial tests written from the specification, not the implementation.
// Each test targets a specific bug verified against the source code.
// RED tests indicate real bugs; GREEN tests validate invariants.
// =============================================================================

// MARK: - SandboxNaming: Unicode and portability

struct AdversarialSandboxNamingTests {
    // Bug #1: CharacterSet.alphanumerics includes Unicode letters (é, ñ, CJK),
    // not just ASCII [a-z0-9]. The sanitize function allows non-ASCII characters
    // through into sandbox names.
    //
    // Portability concern: Container IDs with non-ASCII characters are a hazard
    // for OCI runtimes, filesystem encoding assumptions, and shell escaping.
    // The existing green test `unicodeDirectoryNamePreserved` documents this as
    // intended behavior, but this test argues the design choice is problematic.

    @Test func sandboxNameShouldBeAsciiOnly() {
        let name = SandboxNaming.sandboxName(
            agent: "shell",
            workspacePath: "/Users/test/Code/caf\u{00E9}"
        )
        let allASCII = name.allSatisfy { $0.isASCII }
        #expect(
            allASCII,
            "Sandbox names should contain only ASCII characters for portability (OCI spec, filesystem encoding, shell escaping). Got: \(name)")
    }

    @Test func sandboxNameWithCJKCharactersShouldBeAsciiOnly() {
        let name = SandboxNaming.sandboxName(
            agent: "shell",
            workspacePath: "/Users/test/Code/\u{4E16}\u{754C}"  // "世界"
        )
        let allASCII = name.allSatisfy { $0.isASCII }
        #expect(
            allASCII,
            "CJK characters in workspace path should not leak into sandbox name. Got: \(name)")
    }

    @Test func sandboxNameWithAccentedAgentShouldBeAsciiOnly() {
        let name = SandboxNaming.sandboxName(
            agent: "ren\u{00E9}",  // "rené"
            workspacePath: "/Users/test/Code/project"
        )
        let allASCII = name.allSatisfy { $0.isASCII }
        #expect(
            allASCII,
            "Non-ASCII agent name should be sanitized to ASCII. Got: \(name)")
    }

    // Property: sandboxName output should never contain consecutive dashes.
    // Complements EdgeCaseBugTests #11 (empty agent produces double-dash).
    @Test func sandboxNameNeverContainsConsecutiveDashes() {
        let names = [
            SandboxNaming.sandboxName(agent: "", workspacePath: "/path/to/project"),
            SandboxNaming.sandboxName(agent: "///", workspacePath: "/path/to/project"),
            SandboxNaming.sandboxName(agent: "shell", workspacePath: "/"),
            SandboxNaming.sandboxName(agent: "...", workspacePath: "/path/to/project"),
        ]
        for name in names {
            #expect(
                !name.contains("--"),
                "Sandbox name should not contain consecutive dashes: \(name)")
        }
    }
}

// MARK: - DomainFilter: IPv4-mapped IPv6 cross-family matching

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

// MARK: - NetworkPolicy equality: normalization gaps

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

// MARK: - SandboxManager: extraWorkspacesLabel ordering

struct AdversarialSandboxManagerTests {
    // Bug #7: extraWorkspacesLabel is order-dependent for :ro dedup.
    // The `seen` set deduplicates by resolved path, but the :ro annotation
    // comes from the first occurrence. Different input order → different labels.
    // This causes spurious extraWorkspaceMismatch errors on sandbox reuse.

    @Test func extraWorkspacesLabelOrderIndependentForReadOnly() {
        let tmp = FileManager.default.temporaryDirectory.path
        let extra = "\(tmp)/adversarial-ws-test"
        try? FileManager.default.createDirectory(atPath: extra, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: extra) }

        let label1 = SandboxManager.extraWorkspacesLabel(["\(extra):ro", extra])
        let label2 = SandboxManager.extraWorkspacesLabel([extra, "\(extra):ro"])
        #expect(
            label1 == label2,
            "Same paths with different :ro ordering should produce identical labels. Got '\(label1)' vs '\(label2)'")
    }

    @Test func extraWorkspacesLabelOrderIndependentMultiplePaths() {
        let tmp = FileManager.default.temporaryDirectory.path
        let a = "\(tmp)/adversarial-ws-a"
        let b = "\(tmp)/adversarial-ws-b"
        try? FileManager.default.createDirectory(atPath: a, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(atPath: b, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(atPath: a)
            try? FileManager.default.removeItem(atPath: b)
        }

        // Different ordering of the same two paths should produce the same label.
        let label1 = SandboxManager.extraWorkspacesLabel([a, b])
        let label2 = SandboxManager.extraWorkspacesLabel([b, a])
        #expect(
            label1 == label2,
            "Extra workspace labels should be order-independent. Got '\(label1)' vs '\(label2)'")
    }
}

// MARK: - Property and invariant tests

struct AdversarialPropertyTests {
    /// deduplicateEnvironment should be idempotent: applying it twice
    /// produces the same result as applying it once.
    @Test func deduplicateEnvironmentIsIdempotent() {
        let input: [(key: String, value: String)] = [
            ("FOO", "a"), ("BAR", "b"), ("FOO", "c"), ("BAZ", "d"), ("BAR", "e"),
        ]
        let once = deduplicateEnvironment(input)
        // Parse the output back to tuples and dedup again.
        let parsed = once.compactMap { parseEnvEntry($0) }
        let twice = deduplicateEnvironment(parsed)
        #expect(
            once == twice,
            "deduplicateEnvironment should be idempotent")
    }

    /// After deduplication, each key should appear exactly once.
    @Test func deduplicateEnvironmentProducesUniqueKeys() {
        let input: [(key: String, value: String)] = [
            ("A", "1"), ("B", "2"), ("A", "3"), ("C", "4"), ("B", "5"), ("A", "6"),
        ]
        let result = deduplicateEnvironment(input)
        let keys = result.compactMap { parseEnvEntry($0)?.key }
        #expect(
            keys.count == Set(keys).count,
            "Each key should appear exactly once after deduplication")
    }

    // Last-writer-wins: the LAST value for each key should be preserved.
    @Test func deduplicateEnvironmentLastWriterWins() throws {
        let input: [(key: String, value: String)] = [
            ("KEY", "first"), ("KEY", "middle"), ("KEY", "last"),
        ]
        let result = deduplicateEnvironment(input)
        let value = try parseEnvEntry(#require(result.first))?.value
        #expect(
            value == "last",
            "Last occurrence of a key should win. Got: \(value ?? "nil")")
    }

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

    /// SandboxNaming.sandboxName should be deterministic.
    @Test func sandboxNameIsDeterministic() {
        let a = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/test/project")
        let b = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/test/project")
        #expect(a == b, "Same inputs should produce identical sandbox names")
    }

    /// SandboxNaming.shortHash should produce exactly 8 hex characters.
    @Test func shortHashIsEightHexChars() {
        let inputs = ["", "/", "/Users/test", "a very long path " + String(repeating: "x", count: 1000)]
        for input in inputs {
            let hash = SandboxNaming.shortHash(input)
            #expect(hash.count == 8, "shortHash should be 8 hex chars, got \(hash.count) for input length \(input.count)")
            #expect(
                hash.allSatisfy { "0123456789abcdef".contains($0) },
                "shortHash should contain only hex characters")
        }
    }

    /// parseEnvEntry roundtrip: if it succeeds, reconstructing the string
    /// and re-parsing should yield the same result.
    @Test func parseEnvEntryRoundtrip() {
        let entries = ["KEY=value", "A=", "FOO=bar=baz", "X=a b c", "EMPTY="]
        for entry in entries {
            guard let (key, value) = parseEnvEntry(entry) else {
                Issue.record("parseEnvEntry should succeed for '\(entry)'")
                continue
            }
            let reconstructed = "\(key)=\(value)"
            let reparsed = parseEnvEntry(reconstructed)
            #expect(
                reparsed?.key == key && reparsed?.value == value,
                "Roundtrip failed for '\(entry)': reconstructed '\(reconstructed)' parsed to \(String(describing: reparsed))")
        }
    }
}
