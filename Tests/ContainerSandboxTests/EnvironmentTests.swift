import ContainerResource
import Foundation
@testable import sandbox
import Testing

struct ExecEnvironmentTests {
    // MARK: - Layer ordering

    @Test func baseEnvIsPreserved() {
        let env = SandboxManager.execEnvironment(base: ["PATH=/usr/bin", "HOME=/root"])
        #expect(env.contains("PATH=/usr/bin"))
        #expect(env.contains("HOME=/root"))
    }

    @Test func extrasOverrideBase() {
        let env = SandboxManager.execEnvironment(
            base: ["FOO=base"],
            extras: ["FOO=extra"]
        )
        #expect(env.contains("FOO=extra"))
        #expect(!env.contains("FOO=base"))
    }

    @Test func termPresentWhenTTY() {
        let env = SandboxManager.execEnvironment(base: [], tty: true)
        #expect(env.contains("TERM=xterm-256color"))
    }

    @Test func termAbsentWithoutTTY() {
        let env = SandboxManager.execEnvironment(base: [])
        #expect(!env.contains { $0.hasPrefix("TERM=") })
    }

    @Test func extrasOverrideTerm() {
        let env = SandboxManager.execEnvironment(
            base: [],
            extras: ["TERM=dumb"],
            tty: true
        )
        #expect(env.contains("TERM=dumb"))
        #expect(!env.contains("TERM=xterm-256color"))
    }

    @Test func proxyVarsAlwaysPresent() {
        let env = SandboxManager.execEnvironment(base: [])
        let keys = Set(env.compactMap { parseEnvEntry($0)?.key })
        #expect(keys.contains("HTTPS_PROXY"))
        #expect(keys.contains("https_proxy"))
        #expect(keys.contains("NO_PROXY"))
        #expect(keys.contains("no_proxy"))
    }

    @Test func proxyVarsHaveCorrectValues() {
        let env = SandboxManager.execEnvironment(base: [])
        let expectedUrl = "http://127.0.0.1:\(ProxyManager.proxyPort)"
        let httpsProxy = env.first { $0.hasPrefix("HTTPS_PROXY=") }
        let noProxy = env.first { $0.hasPrefix("NO_PROXY=") }
        #expect(httpsProxy == "HTTPS_PROXY=\(expectedUrl)")
        #expect(noProxy == "NO_PROXY=localhost,127.0.0.1",
                "NO_PROXY must include localhost and 127.0.0.1 to avoid proxying container-local traffic")
    }

    @Test func proxyVarsOverrideExtras() {
        // Proxy vars are added last, so they should win over caller extras
        let env = SandboxManager.execEnvironment(
            base: [],
            extras: ["HTTPS_PROXY=http://custom:8080"]
        )
        let httpsProxy = env.first { $0.hasPrefix("HTTPS_PROXY=") }
        #expect(httpsProxy == "HTTPS_PROXY=http://127.0.0.1:\(ProxyManager.proxyPort)")
    }

    // MARK: - Deduplication

    @Test func noDuplicateKeys() {
        let env = SandboxManager.execEnvironment(
            base: ["FOO=1", "BAR=2", "FOO=3"],
            extras: ["BAR=4", "BAZ=5"]
        )
        let keys = env.compactMap { parseEnvEntry($0)?.key }
        #expect(keys.count == Set(keys).count, "Found duplicate keys in environment")
    }

    @Test func lastWriterWinsWithinBase() {
        let env = SandboxManager.execEnvironment(
            base: ["FOO=first", "FOO=second"]
        )
        #expect(env.contains("FOO=second"))
        #expect(!env.contains("FOO=first"))
    }

    // MARK: - Malformed entries

    @Test func malformedEntriesSkipped() {
        let env = SandboxManager.execEnvironment(
            base: ["GOOD=value", "NO_EQUALS", "=empty_key", "ALSO_GOOD=val"],
            extras: ["BARE_KEY"]
        )
        // "NO_EQUALS" has no =, should be skipped
        #expect(!env.contains { $0.hasPrefix("NO_EQUALS") })
        // "=empty_key" has empty key, should be skipped
        #expect(!env.contains { $0 == "=empty_key" })
        // "BARE_KEY" has no =, should be skipped
        #expect(!env.contains { $0.hasPrefix("BARE_KEY") })
        // Good entries survive
        #expect(env.contains("GOOD=value"))
        #expect(env.contains("ALSO_GOOD=val"))
    }

    @Test func emptyValuePreserved() {
        let env = SandboxManager.execEnvironment(
            base: ["EMPTY_VAL="]
        )
        #expect(env.contains("EMPTY_VAL="))
    }

    // MARK: - Format contract

    @Test func allEntriesHaveKeyEqualsValueFormat() {
        let env = SandboxManager.execEnvironment(
            base: ["PATH=/usr/bin", "HOME=/root"],
            extras: ["CUSTOM=val"]
        )
        for entry in env {
            let parsed = parseEnvEntry(entry)
            #expect(parsed != nil, "Entry '\(entry)' is not KEY=VALUE format")
            if let (key, _) = parsed {
                #expect(!key.isEmpty, "Entry '\(entry)' has empty key")
            }
        }
    }
}

struct ExtraWorkspacesLabelTests {
    @Test func emptyListProducesEmptyString() {
        #expect(SandboxManager.extraWorkspacesLabel([]) == "")
    }

    @Test func orderIndependent() {
        let label1 = SandboxManager.extraWorkspacesLabel(["/b", "/a"])
        let label2 = SandboxManager.extraWorkspacesLabel(["/a", "/b"])
        #expect(label1 == label2)
    }

    @Test func readOnlySuffixPreserved() {
        let label = SandboxManager.extraWorkspacesLabel(["/some/path:ro"])
        #expect(label.hasSuffix(":ro"))
    }

    @Test func multipleWorkspacesSeparatedByComma() {
        let label = SandboxManager.extraWorkspacesLabel(["/a", "/b"])
        #expect(label.contains(","))
    }
}

// MARK: - Adversarial: parseWorkspacePath

struct ParseWorkspacePathAdversarialTests {
    @Test func colonRoSuffixIsAmbiguous() {
        // If a directory is literally named "data:ro", it's indistinguishable
        // from requesting "/path/data" as read-only
        let (path, readOnly) = SandboxManager.parseWorkspacePath("/path/data:ro")
        #expect(readOnly == true)
        #expect(path == "/path/data")
        // This documents the limitation: no escaping mechanism exists
    }

    @Test func emptyWorkspacePath() {
        let (path, readOnly) = SandboxManager.parseWorkspacePath("")
        #expect(path == "")
        #expect(readOnly == false)
    }

    @Test func justColonRo() {
        let (path, readOnly) = SandboxManager.parseWorkspacePath(":ro")
        #expect(path == "")
        #expect(readOnly == true)
    }

    @Test func multipleEqualsInEnvValue() {
        // "KEY=a=b=c" should keep everything after first = as the value
        let env = SandboxManager.execEnvironment(
            base: ["CONFIG=host=localhost=port=5432"]
        )
        #expect(env.contains("CONFIG=host=localhost=port=5432"))
    }

    @Test func newlineInEnvValue() {
        // Newlines in values could be an injection vector in some contexts
        let env = SandboxManager.execEnvironment(
            base: ["SCRIPT=echo hello\nrm -rf /"]
        )
        let entry = env.first { $0.hasPrefix("SCRIPT=") }
        #expect(entry == "SCRIPT=echo hello\nrm -rf /")
    }
}

// MARK: - TERM injection consistency between exec and run paths

struct TermInjectionTests {
    @Test func bothPathsInjectTERMForTTY() {
        // Both execEnvironment (exec path) and processConfiguration (run path)
        // should inject TERM when TTY is requested, matching Docker's behavior.
        let execEnv = SandboxManager.execEnvironment(base: ["PATH=/usr/bin"], tty: true)
        #expect(execEnv.contains { $0.hasPrefix("TERM=") },
                "exec path should inject TERM for TTY sessions")

        let template = ShellTemplate()
        let config = template.processConfiguration(
            baseConfig: ProcessConfiguration(
                executable: "/bin/bash", arguments: [],
                environment: ["PATH=/usr/bin"]
            ),
            workingDirectory: "/tmp"
        )
        #expect(config.environment.contains { $0.hasPrefix("TERM=") },
                "run path should inject TERM for TTY sessions")
    }

    @Test func execPathOmitsTERMWithoutTTY() {
        let env = SandboxManager.execEnvironment(base: ["PATH=/usr/bin"], tty: false)
        #expect(!env.contains { $0.hasPrefix("TERM=") },
                "non-TTY exec should not inject TERM")
    }
}
