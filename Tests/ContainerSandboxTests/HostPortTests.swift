import Testing

@testable import sandbox

struct HostPortTests {
    // MARK: - Standard cases

    @Test func simpleHostPort() {
        let (host, port, malformed) = parseHostPort("example.com:443")
        #expect(host == "example.com")
        #expect(port == 443)
        #expect(!malformed)
    }

    @Test func hostOnly() {
        let (host, port, malformed) = parseHostPort("example.com")
        #expect(host == "example.com")
        #expect(port == nil)
        #expect(!malformed)
    }

    @Test func ipv6WithPort() {
        let (host, port, malformed) = parseHostPort("[::1]:443")
        #expect(host == "::1")
        #expect(port == 443)
        #expect(!malformed)
    }

    @Test func ipv6WithoutPort() {
        let (host, port, malformed) = parseHostPort("[::1]")
        #expect(host == "::1")
        #expect(port == nil)
        #expect(!malformed)
    }

    // MARK: - Edge cases: empty/minimal inputs

    @Test func emptyString() {
        let (host, port, malformed) = parseHostPort("")
        #expect(host == "")
        #expect(port == nil)
        #expect(!malformed)
    }

    @Test func justAColon() {
        let (host, port, malformed) = parseHostPort(":")
        #expect(host == "")
        #expect(port == nil)
        // ':' is a port separator with no port suffix — malformed.
        #expect(malformed)
    }

    // MARK: - Edge cases: malformed ports

    @Test func trailingColonFlaggedMalformed() {
        let (host, port, malformed) = parseHostPort("host:")
        #expect(host == "host")
        #expect(port == nil)
        #expect(malformed)
    }

    @Test func nonNumericPortFlaggedMalformed() {
        let (host, port, malformed) = parseHostPort("host:abc")
        #expect(host == "host")
        #expect(port == nil)
        #expect(malformed)
    }

    @Test func negativePortFlaggedMalformed() {
        let (host, port, malformed) = parseHostPort("host:-1")
        #expect(host == "host")
        #expect(port == nil)
        #expect(malformed)
    }

    @Test func zeroPortAccepted() {
        let (host, port, malformed) = parseHostPort("host:0")
        #expect(host == "host")
        // Port 0 is technically valid (ephemeral) but unusual
        #expect(port == 0)
        #expect(!malformed)
    }

    @Test func hugePortFlaggedMalformed() {
        // Port 99999 exceeds valid range (0-65535).
        let (host, port, malformed) = parseHostPort("host:99999")
        #expect(host == "host")
        #expect(port == nil)
        #expect(malformed, "out-of-range port must be flagged so callers don't coerce to default")
    }

    @Test func portWithLeadingZeros() {
        let (host, port, malformed) = parseHostPort("host:0443")
        #expect(host == "host")
        // Int("0443") == 443, leading zeros silently stripped
        #expect(port == 443)
        #expect(!malformed)
    }

    // MARK: - Edge cases: IPv6 without brackets

    @Test func bareIPv6ReturnedAsHost() {
        // Bare IPv6 without brackets — should not misparse as host:port
        let (host, port, malformed) = parseHostPort("::1")
        #expect(host == "::1")
        #expect(port == nil)
        #expect(!malformed)
    }

    @Test func bareIPv6FullReturnedAsHost() {
        let (host, port, malformed) = parseHostPort("2001:db8::1")
        #expect(host == "2001:db8::1")
        #expect(port == nil)
        #expect(!malformed)
    }

    // MARK: - Edge cases: bracket malformations

    @Test func incompleteBracketReturnedAsHost() {
        // "[::1" — no closing bracket, return as-is without misparsing
        let (host, port, malformed) = parseHostPort("[::1")
        #expect(host == "[::1")
        #expect(port == nil)
        #expect(!malformed)
    }

    @Test func emptyBrackets() {
        let (host, port, malformed) = parseHostPort("[]")
        #expect(host == "")
        #expect(port == nil)
        #expect(!malformed)
    }

    @Test func ipv6BracketWithNonNumericPortFlaggedMalformed() {
        let (host, port, malformed) = parseHostPort("[::1]:abc")
        #expect(host == "::1")
        #expect(port == nil)
        #expect(malformed)
    }

    @Test func ipv6BracketWithEmptyPortFlaggedMalformed() {
        let (host, port, malformed) = parseHostPort("[::1]:")
        #expect(host == "::1")
        #expect(port == nil)
        #expect(malformed)
    }

    @Test func ipv6BracketWithJunkAfterFlaggedMalformed() {
        let (host, port, malformed) = parseHostPort("[::1]junk")
        #expect(host == "::1")
        #expect(port == nil)
        #expect(malformed)
    }
}

struct ParseEnvEntryTests {
    @Test func multipleEqualsInValue() {
        // "KEY=a=b=c" should split on first = only
        let result = parseEnvEntry("KEY=a=b=c")
        #expect(result?.key == "KEY")
        #expect(result?.value == "a=b=c")
    }

    @Test func valueIsJustEquals() {
        let result = parseEnvEntry("KEY==")
        #expect(result?.key == "KEY")
        #expect(result?.value == "=")
    }

    @Test func doubleEquals() {
        // "==" → split gives ["", "="], empty key → nil
        let result = parseEnvEntry("==")
        #expect(result == nil)
    }

    @Test func emptyString() {
        let result = parseEnvEntry("")
        #expect(result == nil)
    }

    @Test func newlineInValue() {
        let result = parseEnvEntry("KEY=line1\nline2")
        #expect(result?.key == "KEY")
        #expect(result?.value == "line1\nline2")
    }

    @Test func nullByteInValue() {
        let result = parseEnvEntry("KEY=val\0ue")
        #expect(result?.key == "KEY")
        #expect(result?.value == "val\0ue")
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

// MARK: - parseHostPort whitespace regressions

struct ParseHostPortWhitespaceBugs {
    @Test func trailingWhitespaceBreaksPortParsing() {
        // Int("443 ") returns nil because of the trailing space,
        // so the port is silently lost.
        let (host, port, _) = parseHostPort("host:443 ")
        #expect(host == "host")
        #expect(port == 443, "Trailing space should not break port parsing")
    }

    @Test func leadingWhitespacePreservedInHostname() {
        // The leading space becomes part of the hostname, so " host"
        // won't match "host" in domain filter comparisons.
        let (host, port, _) = parseHostPort(" host:443")
        #expect(host == "host", "Leading whitespace should be trimmed from hostname")
        #expect(port == 443)
    }

    @Test func tabCharacterPreservedInHostname() {
        // Tab before the colon becomes part of the hostname.
        let (host, _, _) = parseHostPort("host\t:443")
        #expect(host == "host", "Tab character should be trimmed from hostname")
    }
}
