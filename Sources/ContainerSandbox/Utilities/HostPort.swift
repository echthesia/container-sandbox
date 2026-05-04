/// Split a "KEY=VALUE" string into its components.
/// Returns nil if no `=` is present.
func parseEnvEntry(_ entry: String) -> (key: String, value: String)? {
    let parts = entry.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2, !parts[0].isEmpty else { return nil }
    return (String(parts[0]), String(parts[1]))
}

/// Deduplicate environment variable entries with last-writer-wins semantics.
/// Returns an array of "KEY=VALUE" strings with only the last occurrence of each key.
func deduplicateEnvironment(_ envMap: [(key: String, value: String)]) -> [String] {
    var seen = Set<String>()
    var env: [String] = []
    for (key, value) in envMap.reversed() {
        if seen.insert(key).inserted {
            env.append("\(key)=\(value)")
        }
    }
    env.reverse()
    return env
}

/// Parse a "host:port" string into its components.
///
/// Handles IPv6 brackets (`[::1]:443`), plain `host:port`, and bare hostnames.
/// Returns `port = nil` when no port is specified. Sets `malformed = true`
/// when a port suffix was present but couldn't be parsed (non-numeric,
/// negative, out of range, empty after the colon). Callers that default a
/// missing port to 80/443 must reject malformed input instead — otherwise
/// `target:99999` silently coerces to the default port and any future
/// port-scoped policy rule can be bypassed by writing a syntactically
/// broken port.
func parseHostPort(_ input: String) -> (host: String, port: Int?, malformed: Bool) {
    let input = input.filter { !$0.isWhitespace }

    // Handle IPv6 in brackets: [::1]:443
    if input.hasPrefix("["), let bracketEnd = input.firstIndex(of: "]") {
        let host = String(input[input.index(after: input.startIndex)..<bracketEnd])
        let afterBracket = input[input.index(after: bracketEnd)...]
        if afterBracket.isEmpty {
            return (host, nil, false)
        }
        if afterBracket.hasPrefix(":") {
            let portStr = afterBracket.dropFirst()
            if let port = Int(portStr), port >= 0, port <= 65535 {
                return (host, port, false)
            }
            // Bracket followed by ":..." — malformed port (empty, non-numeric,
            // or out of range).
            return (host, nil, true)
        }
        // Trailing junk after the bracket that isn't ":port".
        return (host, nil, true)
    }

    // Bare IPv6 (multiple colons, no brackets) — return as-is, no port.
    if input.filter({ $0 == ":" }).count > 1 {
        return (input, nil, false)
    }

    // Split on last colon only if the suffix is a valid port number.
    if let lastColon = input.lastIndex(of: ":") {
        let host = String(input[..<lastColon])
        let possiblePort = String(input[input.index(after: lastColon)...])
        if let port = Int(possiblePort), port >= 0, port <= 65535 {
            return (host, port, false)
        }
        return (host, nil, true)
    }

    return (input, nil, false)
}
