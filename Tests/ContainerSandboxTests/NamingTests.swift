import Testing

@testable import sandbox

struct NamingTests {
    @Test func includesDirnameAndHash() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        #expect(name.hasPrefix("sandbox-claude-my-project-"))
        #expect(name.count > "sandbox-claude-my-project-".count)
    }

    @Test func isDeterministic() {
        let a = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        let b = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        #expect(a == b)
    }

    @Test func differsByFullPath() {
        let a = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project")
        let b = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/other/Code/my-project")
        #expect(a != b)
        // Both start with the same dirname prefix
        #expect(a.hasPrefix("sandbox-claude-my-project-"))
        #expect(b.hasPrefix("sandbox-claude-my-project-"))
    }

    @Test func lowercasesDirname() {
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/MyProject")
        #expect(name.contains("-myproject-"))
    }

    @Test func sanitizesSpecialCharacters() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my project (copy)")
        #expect(name.contains("-myprojectcopy-"))
    }

    @Test func preservesHyphensUnderscoresPeriods() {
        let name = SandboxNaming.sandboxName(agent: "claude", workspacePath: "/Users/me/Code/my-project_v2.0")
        #expect(name.contains("-my-project_v2.0-"))
    }

    @Test func isSandboxNameMatchesPrefix() {
        #expect(SandboxNaming.isSandboxName("sandbox-claude-myproject-abcd1234"))
        #expect(SandboxNaming.isSandboxName("sandbox-shell-foo-1234abcd"))
        #expect(!SandboxNaming.isSandboxName("buildkit"))
        #expect(!SandboxNaming.isSandboxName("my-container"))
        #expect(!SandboxNaming.isSandboxName(""))
    }

    @Test func isSandboxNameMinimalPrefix() {
        // "sandbox-" is the bare minimum that matches the prefix check
        #expect(SandboxNaming.isSandboxName("sandbox-"))
        // But does it represent a valid sandbox? Probably not.
    }

    // MARK: - Adversarial: path edge cases

    @Test func rootPathProducesValidName() {
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/")
        #expect(name.hasPrefix("sandbox-shell-"))
        #expect(!name.isEmpty)
        // lastPathComponent of "/" might be "/" which sanitizes to "workspace"
        #expect(name.contains("workspace"))
    }

    @Test func pathWithOnlySpecialCharsUsesWorkspaceFallback() {
        // A dirname of only spaces/parens should sanitize to empty → "workspace"
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/   ")
        #expect(name.contains("workspace"))
    }

    @Test func unicodeDirectoryNameStrippedToAscii() {
        // Unicode characters are stripped; sanitize falls back to "workspace" when
        // no ASCII alphanumerics remain. Sandbox names must be ASCII-only for
        // portability across OCI runtimes, filesystem encodings, and shells.
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/café")
        #expect(name.allSatisfy { $0.isASCII })
        #expect(name.contains("caf"))
        #expect(!name.contains("é"))
    }

    @Test func veryLongDirectoryNameTruncated() {
        let longDir = String(repeating: "a", count: 500)
        let name = SandboxNaming.sandboxName(agent: "shell", workspacePath: "/Users/me/Code/\(longDir)")
        // Dirname is truncated so the full name fits the relay-socket staging-path
        // limit: id ≤ 42 chars keeps `/run/container/<id>/sockets/<UUID>.sock`
        // under Linux's 108-byte sun_path limit.
        #expect(name.count <= SandboxNaming.maxNameLength)
        #expect(!name.contains(longDir))
        #expect(name.hasPrefix("sandbox-shell-"))
    }

    @Test func longNameRespectsRelaySocketBudget() {
        // Worst-case: 200-char workspace basename, 6-char agent name. Result
        // must still fit so the in-guest socket relay can bind.
        let name = SandboxNaming.sandboxName(
            agent: "claude",
            workspacePath: "/x/" + String(repeating: "z", count: 200)
        )
        #expect(name.count <= SandboxNaming.maxNameLength)
    }

    @Test func validateNameRejectsOverlongNames() {
        let tooLong = "sandbox-claude-" + String(repeating: "x", count: 100)
        #expect(throws: SandboxError.self) {
            try SandboxNaming.validateName(tooLong)
        }
    }

    @Test func hashCollisionResistance() {
        // Generate many names with same basename but different parent paths
        // and verify no hash collisions in the batch
        var hashes = Set<String>()
        for i in 0..<1000 {
            let hash = SandboxNaming.shortHash("/path/\(i)/project")
            hashes.insert(hash)
        }
        #expect(hashes.count == 1000, "Found hash collision in 1000 distinct paths")
    }
}

// MARK: - Adversarial: Unicode and portability

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

// MARK: - Input validation regressions

struct SandboxNamingInputValidationBugs {
    @Test func agentNameWithPathTraversalSanitized() {
        // The agent name is sanitized — slashes are removed so path traversal
        // via "../" is impossible, and validateName rejects names containing "..".
        let name = SandboxNaming.sandboxName(agent: "../evil", workspacePath: "/path/to/project")
        #expect(
            !name.contains("/"),
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
        #expect(
            !name.contains("/"),
            "Agent name should not contain path separator characters")
    }

    @Test func emptyAgentNameProducesDoubleDash() {
        // An empty agent name produces "sandbox--dirname-hash" with a double dash.
        // The name is used as a container ID and state storage key, so it should
        // be validated or the empty agent rejected.
        let name = SandboxNaming.sandboxName(agent: "", workspacePath: "/path/to/project")
        #expect(
            !name.contains("--"),
            "Empty agent name should not produce a double-dash in the sandbox name")
    }
}

// MARK: - Determinism and hash properties

struct SandboxNamingPropertyTests {
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
}
