import ContainerizationOCI
import ContainerResource
import Foundation
@testable import sandbox
import Testing

// =============================================================================
// Red tests exposing real bugs across the codebase. Each test documents what
// the correct behavior should be and why the current code fails.
// =============================================================================

// MARK: - NetworkPolicy Equality: CIDR normalization gaps

struct NetworkPolicyEqualityBugs {
    @Test func cidrCaseInsensitiveEquality() {
        // normalizedCIDRSet doesn't lowercase the address portion,
        // so "FC00::/7" and "fc00::/7" are treated as different CIDRs
        // despite representing the same network range.
        let a = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["FC00::/7"])
        let b = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["fc00::/7"])
        #expect(a == b, "CIDRs should be compared case-insensitively for hex digits")
    }

    @Test func ipv6NormalizationInCidrEquality() {
        // Two string representations of the same IPv6 address are not
        // recognized as equal because normalizedCIDRSet uses string comparison.
        let a = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["::1/128"])
        let b = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                              blockedCIDRs: ["0000:0000:0000:0000:0000:0000:0000:0001/128"])
        #expect(a == b, "Equivalent IPv6 addresses should be equal in CIDR comparison")
    }
}

// MARK: - DomainFilter: pattern normalization gaps

struct DomainFilterPatternNormalizationBugs {
    // evaluate() strips trailing dots from the incoming host, but patterns in
    // allowedHosts/blockedHosts are not normalized. In DNS, "example.com." and
    // "example.com" are the same name, so patterns should be normalized too.

    @Test func allowlistPatternTrailingDotNotStripped() {
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com."]))
        #expect(filter.evaluate(host: "example.com", port: 443) == .allow,
                "Pattern 'example.com.' should match host 'example.com'")
    }

    @Test func blocklistPatternTrailingDotNotStripped() {
        let policy = NetworkPolicy(direction: .allow, allowedHosts: [],
                                   blockedHosts: ["evil.com."], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "evil.com", port: 443) != .allow,
                "Blocked pattern 'evil.com.' should block 'evil.com'")
    }

    @Test func wildcardAllowlistPatternTrailingDotNotStripped() {
        // "*.example.com." → suffix is ".example.com." which won't match
        // "sub.example.com" because the host doesn't end with ".example.com."
        let filter = DomainFilter(policy: .deny(allowedHosts: ["*.example.com."]))
        #expect(filter.evaluate(host: "sub.example.com", port: 443) == .allow,
                "Wildcard pattern '*.example.com.' should match subdomains")
    }

    @Test func wildcardBlocklistPatternTrailingDotNotStripped() {
        let policy = NetworkPolicy(direction: .allow, allowedHosts: [],
                                   blockedHosts: ["*.evil.com."], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "sub.evil.com", port: 443) != .allow,
                "Wildcard blocked pattern '*.evil.com.' should block subdomains")
    }
}

// MARK: - DomainFilter: whitespace and multi-dot edge cases

struct DomainFilterWhitespaceBugs {
    @Test func patternWithLeadingWhitespaceDoesNotMatch() {
        // Leading whitespace in a pattern prevents exact match because
        // " evil.com" != "evil.com". Patterns should be trimmed.
        let policy = NetworkPolicy(direction: .allow, allowedHosts: [],
                                   blockedHosts: [" evil.com"], blockedCIDRs: [])
        let filter = DomainFilter(policy: policy)
        #expect(filter.evaluate(host: "evil.com", port: 443) != .allow,
                "Pattern with leading whitespace should still match the host")
    }

    @Test func cidrWithLeadingWhitespaceFailsToBlock() {
        // Leading whitespace makes inet_pton fail, silently disabling the CIDR rule.
        let policy = NetworkPolicy(direction: .deny, allowedHosts: [], blockedHosts: [],
                                   blockedCIDRs: [" 10.0.0.0/8"])
        let filter = DomainFilter(policy: policy)
        #expect(filter.isBlockedCIDR("10.0.0.1"),
                "Leading whitespace in CIDR should not disable the block rule")
    }

    @Test func multipleTrailingDotsNotFullyStripped() {
        // The code strips exactly one trailing dot. A host with two trailing dots
        // ("example.com..") becomes "example.com." after stripping, which doesn't
        // match the pattern "example.com".
        let filter = DomainFilter(policy: .deny(allowedHosts: ["example.com"]))
        #expect(filter.evaluate(host: "example.com..", port: 443) == .allow,
                "All trailing dots should be stripped to match the base domain")
    }
}

// MARK: - parseHostPort: whitespace handling

struct ParseHostPortWhitespaceBugs {
    @Test func trailingWhitespaceBreaksPortParsing() {
        // Int("443 ") returns nil because of the trailing space,
        // so the port is silently lost.
        let (host, port) = parseHostPort("host:443 ")
        #expect(host == "host")
        #expect(port == 443, "Trailing space should not break port parsing")
    }

    @Test func leadingWhitespacePreservedInHostname() {
        // The leading space becomes part of the hostname, so " host"
        // won't match "host" in domain filter comparisons.
        let (host, port) = parseHostPort(" host:443")
        #expect(host == "host", "Leading whitespace should be trimmed from hostname")
        #expect(port == 443)
    }

    @Test func tabCharacterPreservedInHostname() {
        // Tab before the colon becomes part of the hostname.
        let (host, _) = parseHostPort("host\t:443")
        #expect(host == "host", "Tab character should be trimmed from hostname")
    }
}

// MARK: - SandboxManager: duplicate extra workspace mounts

private let edgeCaseWorkspace = FileManager.default.temporaryDirectory
    .appendingPathComponent("sandbox-edgecase-workspace").path
private let edgeCaseExtra = FileManager.default.temporaryDirectory
    .appendingPathComponent("sandbox-edgecase-extra").path

struct SandboxManagerDuplicateMountBugs {
    init() {
        try? FileManager.default.createDirectory(
            atPath: edgeCaseWorkspace, withIntermediateDirectories: true
        )
        try? FileManager.default.createDirectory(
            atPath: edgeCaseExtra, withIntermediateDirectories: true
        )
    }

    private func makeTestManager() -> (SandboxManager, FakeContainerOperations) {
        let containers = FakeContainerOperations()
        let images = FakeImageOperations()
        images.existingImages = [
            "container-sandbox-claude:latest", "docker.io/ubuntu:24.04",
        ]
        let manager = SandboxManager(
            containers: containers,
            images: images,
            kernels: FakeKernelProvider(),
            sessions: SessionTracker(storage: FakeSessionStorage(), pidIsAlive: { _ in false }),
            proxy: ProxyManager(launcher: FakeProxyLauncher(), stateStorage: FakeProxyStateStorage()),
            libexecPath: testLibexecPath
        )
        return (manager, containers)
    }

    @Test func duplicateExtraWorkspacesCreateConflictingMounts() async throws {
        // Passing the same path twice in extraWorkspaces (once r/w, once r/o)
        // creates two virtiofs mounts at the same destination. The dedup check
        // only compares against the primary workspace, not among extras.
        let (manager, containers) = makeTestManager()

        _ = try await manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: edgeCaseWorkspace,
            extraWorkspaces: [edgeCaseExtra, "\(edgeCaseExtra):ro"]
        )

        let config = containers.createdConfigs[0]
        let resolvedExtra = SandboxManager.resolveWorkspacePath(edgeCaseExtra)
        let mountsAtDest = config.mounts.filter { $0.destination == resolvedExtra }
        #expect(mountsAtDest.count <= 1,
                "Should not create \(mountsAtDest.count) conflicting mounts at '\(resolvedExtra)'")
    }

    @Test func sameExtraWorkspaceDifferentFormsCreatesDuplicateMounts() async throws {
        // The same directory expressed as two different path forms (with/without
        // trailing slash or ../) would both be resolved to the same destination,
        // creating duplicate mounts.
        let (manager, containers) = makeTestManager()

        let parent = FileManager.default.temporaryDirectory.path
        let extra1 = edgeCaseExtra
        let extra2 = "\(parent)/sandbox-edgecase-extra/../sandbox-edgecase-extra"

        _ = try await manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: edgeCaseWorkspace,
            extraWorkspaces: [extra1, extra2]
        )

        let config = containers.createdConfigs[0]
        let resolvedExtra = SandboxManager.resolveWorkspacePath(edgeCaseExtra)
        let mountsAtDest = config.mounts.filter { $0.destination == resolvedExtra }
        #expect(mountsAtDest.count <= 1,
                "Same directory via different paths should not create duplicate mounts")
    }
}

// MARK: - SandboxManager: label format ambiguity

struct SandboxManagerLabelBugs {
    @Test func extraWorkspaceLabelCommaAmbiguity() {
        // A single path containing a comma produces the same label as two
        // separate paths joined by comma. "/a,/b" (one path: file "b" in
        // directory "a,") collides with two paths "/a" and "/b" joined as "/a,/b".
        let singlePathWithComma = SandboxManager.extraWorkspacesLabel(["/a,/b"])
        let twoSeparatePaths = SandboxManager.extraWorkspacesLabel(["/a", "/b"])
        #expect(singlePathWithComma != twoSeparatePaths,
                "Label for path '/a,/b' should differ from label for paths '/a' + '/b'")
    }
}

// MARK: - SandboxManager: empty and edge-case inputs

struct SandboxManagerInputValidationBugs {
    init() {
        try? FileManager.default.createDirectory(
            atPath: edgeCaseWorkspace, withIntermediateDirectories: true
        )
    }

    private func makeTestManager() -> (SandboxManager, FakeContainerOperations) {
        let containers = FakeContainerOperations()
        let images = FakeImageOperations()
        images.existingImages = [
            "container-sandbox-claude:latest", "docker.io/ubuntu:24.04",
        ]
        let manager = SandboxManager(
            containers: containers,
            images: images,
            kernels: FakeKernelProvider(),
            sessions: SessionTracker(storage: FakeSessionStorage(), pidIsAlive: { _ in false }),
            proxy: ProxyManager(launcher: FakeProxyLauncher(), stateStorage: FakeProxyStateStorage()),
            libexecPath: testLibexecPath
        )
        return (manager, containers)
    }

    @Test func emptyExtraWorkspaceSilentlyMountsCwd() async throws {
        // An empty string in extraWorkspaces resolves to the current working
        // directory via resolveWorkspacePath(""). This silently mounts the
        // entire cwd into the sandbox with no indication to the user.
        let (manager, containers) = makeTestManager()

        _ = try await manager.ensureSandboxExists(
            template: ShellTemplate(),
            workspace: edgeCaseWorkspace,
            extraWorkspaces: [""]
        )

        let config = containers.createdConfigs[0]
        let resolvedCwd = SandboxManager.resolveWorkspacePath("")
        let cwdMounts = config.mounts.filter { $0.destination == resolvedCwd }
        #expect(cwdMounts.isEmpty,
                "Empty string extra workspace should not silently mount '\(resolvedCwd)'")
    }
}

// MARK: - SandboxNaming: agent name not sanitized

struct SandboxNamingInputValidationBugs {
    @Test func agentNameWithPathTraversalSanitized() {
        // The agent name is sanitized — slashes are removed so path traversal
        // via "../" is impossible, and validateName rejects names containing "..".
        let name = SandboxNaming.sandboxName(agent: "../evil", workspacePath: "/path/to/project")
        #expect(!name.contains("/"),
                "Slashes in agent name should be stripped")
        // validateName provides defense-in-depth: even if a crafted name
        // somehow contained "..", it would be rejected before use.
        #expect(throws: SandboxError.self) {
            try SandboxNaming.validateName("sandbox-../evil-project-1234")
        }
    }

    @Test func agentNameWithSlashNotSanitized() {
        // A "/" in the agent name creates nested path components when used
        // as a filename key in state storage.
        let name = SandboxNaming.sandboxName(agent: "agent/name", workspacePath: "/path/to/project")
        #expect(!name.contains("/"),
                "Agent name should not contain path separator characters")
    }

    @Test func emptyAgentNameProducesDoubleDash() {
        // An empty agent name produces "sandbox--dirname-hash" with a double dash.
        // The name is used as a container ID and state storage key, so it should
        // be validated or the empty agent rejected.
        let name = SandboxNaming.sandboxName(agent: "", workspacePath: "/path/to/project")
        #expect(!name.contains("--"),
                "Empty agent name should not produce a double-dash in the sandbox name")
    }
}
