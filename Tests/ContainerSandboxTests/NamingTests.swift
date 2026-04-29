@testable import sandbox
import Testing

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
        for i in 0 ..< 1000 {
            let hash = SandboxNaming.shortHash("/path/\(i)/project")
            hashes.insert(hash)
        }
        #expect(hashes.count == 1000, "Found hash collision in 1000 distinct paths")
    }
}
