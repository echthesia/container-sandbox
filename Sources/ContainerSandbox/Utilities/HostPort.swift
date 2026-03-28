/// Split a "KEY=VALUE" string into its components.
/// Returns nil if no `=` is present.
func parseEnvEntry(_ entry: String) -> (key: String, value: String)? {
    let parts = entry.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2, !parts[0].isEmpty else { return nil }
    return (String(parts[0]), String(parts[1]))
}

/// Parse a "host:port" string into its components.
///
/// Handles IPv6 brackets (`[::1]:443`), plain `host:port`, and bare hostnames.
/// Returns a nil port when none is specified.
func parseHostPort(_ input: String) -> (host: String, port: Int?) {
    // Handle IPv6 in brackets: [::1]:443
    if input.hasPrefix("["), let bracketEnd = input.firstIndex(of: "]") {
        let host = String(input[input.index(after: input.startIndex) ..< bracketEnd])
        let afterBracket = input[input.index(after: bracketEnd)...]
        if afterBracket.hasPrefix(":"), let port = Int(afterBracket.dropFirst()),
           port >= 0, port <= 65535
        {
            return (host, port)
        }
        return (host, nil)
    }

    // Bare IPv6 (multiple colons, no brackets) — return as-is, no port.
    if input.filter({ $0 == ":" }).count > 1 {
        return (input, nil)
    }

    // Split on last colon only if the suffix is a valid port number.
    if let lastColon = input.lastIndex(of: ":") {
        let host = String(input[..<lastColon])
        let possiblePort = String(input[input.index(after: lastColon)...])
        if let port = Int(possiblePort), port >= 0, port <= 65535 {
            return (host, port)
        }
        return (host, nil)
    }

    return (input, nil)
}
