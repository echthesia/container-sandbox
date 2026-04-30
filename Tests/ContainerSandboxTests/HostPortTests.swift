import Testing

@testable import sandbox

struct HostPortTests {
    // MARK: - Standard cases

    @Test func simpleHostPort() {
        let (host, port) = parseHostPort("example.com:443")
        #expect(host == "example.com")
        #expect(port == 443)
    }

    @Test func hostOnly() {
        let (host, port) = parseHostPort("example.com")
        #expect(host == "example.com")
        #expect(port == nil)
    }

    @Test func ipv6WithPort() {
        let (host, port) = parseHostPort("[::1]:443")
        #expect(host == "::1")
        #expect(port == 443)
    }

    @Test func ipv6WithoutPort() {
        let (host, port) = parseHostPort("[::1]")
        #expect(host == "::1")
        #expect(port == nil)
    }

    // MARK: - Edge cases: empty/minimal inputs

    @Test func emptyString() {
        let (host, port) = parseHostPort("")
        #expect(host == "")
        #expect(port == nil)
    }

    @Test func justAColon() {
        let (host, port) = parseHostPort(":")
        // ":" → lastIndex finds colon, possiblePort is "", Int("") fails
        // Falls through to return (":", nil) — colon leaks into host
        #expect(host == "")
        #expect(port == nil)
    }

    // MARK: - Edge cases: malformed ports

    @Test func trailingColonLeaksIntoHost() {
        // "host:" has empty port string, Int("") fails, full input returned as host
        let (host, port) = parseHostPort("host:")
        // Correct behavior: host should be "host", not "host:"
        #expect(host == "host")
        #expect(port == nil)
    }

    @Test func nonNumericPortLeaksIntoHost() {
        // "host:abc" — Int("abc") fails, full input returned as host
        let (host, port) = parseHostPort("host:abc")
        // Correct behavior: host should be "host", not "host:abc"
        #expect(host == "host")
        #expect(port == nil)
    }

    @Test func negativePortAccepted() {
        // Int("-1") succeeds — no range validation
        let (host, port) = parseHostPort("host:-1")
        #expect(host == "host")
        // Correct behavior: negative ports are invalid, should return nil
        #expect(port == nil)
    }

    @Test func zeroPortAccepted() {
        let (host, port) = parseHostPort("host:0")
        #expect(host == "host")
        // Port 0 is technically valid (ephemeral) but unusual
        #expect(port == 0)
    }

    @Test func hugePortAccepted() {
        // Port 99999 exceeds valid range (0-65535) but Int succeeds
        let (host, port) = parseHostPort("host:99999")
        #expect(host == "host")
        // Correct behavior: out-of-range ports should return nil
        #expect(port == nil)
    }

    @Test func portWithLeadingZeros() {
        let (host, port) = parseHostPort("host:0443")
        #expect(host == "host")
        // Int("0443") == 443, leading zeros silently stripped
        #expect(port == 443)
    }

    // MARK: - Edge cases: IPv6 without brackets

    @Test func bareIPv6ReturnedAsHost() {
        // Bare IPv6 without brackets — should not misparse as host:port
        let (host, port) = parseHostPort("::1")
        #expect(host == "::1")
        #expect(port == nil)
    }

    @Test func bareIPv6FullReturnedAsHost() {
        let (host, port) = parseHostPort("2001:db8::1")
        #expect(host == "2001:db8::1")
        #expect(port == nil)
    }

    // MARK: - Edge cases: bracket malformations

    @Test func incompleteBracketReturnedAsHost() {
        // "[::1" — no closing bracket, return as-is without misparsing
        let (host, port) = parseHostPort("[::1")
        #expect(host == "[::1")
        #expect(port == nil)
    }

    @Test func emptyBrackets() {
        let (host, port) = parseHostPort("[]")
        #expect(host == "")
        #expect(port == nil)
    }

    @Test func ipv6BracketWithNonNumericPort() {
        // "[::1]:abc" — Int("abc") fails, port silently dropped
        let (host, port) = parseHostPort("[::1]:abc")
        #expect(host == "::1")
        #expect(port == nil)
    }

    @Test func ipv6BracketWithEmptyPort() {
        let (host, port) = parseHostPort("[::1]:")
        #expect(host == "::1")
        #expect(port == nil)
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
