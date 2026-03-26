/// Parse a "host:port" string into its components.
///
/// Handles IPv6 brackets (`[::1]:443`), plain `host:port`, and bare hostnames.
/// Returns a nil port when none is specified.
func parseHostPort(_ input: String) -> (host: String, port: Int?) {
    // Handle IPv6 in brackets: [::1]:443
    if input.hasPrefix("["), let bracketEnd = input.firstIndex(of: "]") {
        let host = String(input[input.index(after: input.startIndex)..<bracketEnd])
        let afterBracket = input[input.index(after: bracketEnd)...]
        if afterBracket.hasPrefix(":"), let port = Int(afterBracket.dropFirst()) {
            return (host, port)
        }
        return (host, nil)
    }

    // Split on last colon only if the suffix is a valid port number.
    if let lastColon = input.lastIndex(of: ":") {
        let possiblePort = String(input[input.index(after: lastColon)...])
        if let port = Int(possiblePort) {
            return (String(input[..<lastColon]), port)
        }
    }

    return (input, nil)
}
