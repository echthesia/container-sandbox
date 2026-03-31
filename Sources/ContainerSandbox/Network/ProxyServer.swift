import Foundation
import Logging
import NIOCore
import NIOPosix

private let proxyLog = Logger(label: "container-sandbox.proxy")

/// A multi-protocol proxy that listens on a Unix domain socket.
/// Supports HTTP CONNECT (HTTPS tunneling), HTTP forward proxying, and SOCKS5.
/// Filters outbound connections by domain using a DomainFilter.
final class ProxyServer: Sendable {
    let socketPath: String
    let filter: DomainFilter

    init(socketPath: String, filter: DomainFilter) {
        self.socketPath = socketPath
        self.filter = filter
    }

    /// Run the proxy server. Blocks until the server is shut down.
    func run() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)

        do {
            // Remove stale socket file if present.
            unlink(socketPath)

            let serverChannel = try await ServerBootstrap(group: group)
                .serverChannelOption(.backlog, value: 256)
                .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
                .bind(
                    unixDomainSocketPath: socketPath,
                    childChannelInitializer: { channel in
                        channel.eventLoop.makeCompletedFuture {
                            try NIOAsyncChannel<ByteBuffer, ByteBuffer>(
                                wrappingChannelSynchronously: channel
                            )
                        }
                    }
                )

            proxyLog.info("Proxy listening on \(socketPath)")

            // Socket lives inside a 0o700 directory created by ProxyManager — directory
            // permissions gate access, so no chmod needed here.
            try await serverChannel.executeThenClose { connections, _ in
                try await withThrowingDiscardingTaskGroup { group in
                    for try await connection in connections {
                        group.addTask { await self.handleConnection(connection) }
                    }
                }
            }
            try await group.shutdownGracefully()
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    // MARK: - Connection dispatch

    /// Read the first byte to detect protocol, then dispatch to the appropriate handler.
    private func handleConnection(_ channel: NIOAsyncChannel<ByteBuffer, ByteBuffer>) async {
        do {
            try await channel.executeThenClose { inbound, outbound in
                var iterator = inbound.makeAsyncIterator()
                guard let firstBuffer = try await iterator.next() else { return }
                guard let firstByte = firstBuffer.getInteger(
                    at: firstBuffer.readerIndex, as: UInt8.self
                ) else { return }

                // Re-queue the first buffer for the protocol handler.
                var buffer = firstBuffer

                if firstByte == 0x05 {
                    // SOCKS5 greeting always starts with version byte 0x05.
                    try await self.handleSOCKS5(
                        buffer: &buffer, iterator: &iterator,
                        outbound: outbound, channel: channel.channel
                    )
                } else {
                    // Anything else is HTTP (CONNECT for HTTPS tunneling, or plain HTTP).
                    try await self.handleHTTP(
                        buffer: &buffer, iterator: &iterator,
                        outbound: outbound, channel: channel.channel
                    )
                }
            }
        } catch {
            // Connection-level errors are expected (client disconnect, timeout, etc.)
        }
    }

    // MARK: - HTTP Proxy Handler (CONNECT + Forward)

    /// Handle an HTTP proxy request: parse headers, check filter, then either
    /// tunnel (CONNECT) or forward (plain HTTP).
    private func handleHTTP(
        buffer: inout ByteBuffer,
        iterator: inout NIOAsyncChannelInboundStream<ByteBuffer>.AsyncIterator,
        outbound: NIOAsyncChannelOutboundWriter<ByteBuffer>,
        channel: Channel
    ) async throws {
        // Parse the HTTP request line and headers.
        let request = try await parseHTTPRequest(buffer: &buffer, iterator: &iterator)

        if request.method == "CONNECT" {
            try await handleConnect(
                request: request, iterator: &iterator,
                outbound: outbound, channel: channel
            )
        } else {
            try await handleHTTPForward(
                request: request, overflow: buffer,
                iterator: &iterator, outbound: outbound, channel: channel
            )
        }
    }

    /// Handle CONNECT method — extract host:port, check filter, tunnel or reject.
    private func handleConnect(
        request: HTTPRequest,
        iterator: inout NIOAsyncChannelInboundStream<ByteBuffer>.AsyncIterator,
        outbound: NIOAsyncChannelOutboundWriter<ByteBuffer>,
        channel: Channel
    ) async throws {
        let target = request.uri
        let (host, port) = parseConnectTarget(target)

        let decision = filter.evaluate(host: host, port: port)
        switch decision {
        case .allow:
            proxyLog.info("ALLOW CONNECT \(target)")
        case let .deny(reason):
            proxyLog.info("DENY CONNECT \(target): \(reason)")
            try await writeHTTPResponse(
                outbound, allocator: channel.allocator,
                status: 403, reason: "Forbidden", body: "Blocked: \(reason)\n"
            )
            return
        }

        // Connect to the remote host.
        let remoteChannel: NIOAsyncChannel<ByteBuffer, ByteBuffer>
        do {
            remoteChannel = try await connectRemote(
                host: host, port: port, group: channel.eventLoop
            )
        } catch {
            proxyLog.error("Failed to connect to \(host):\(port): \(error)")
            try await writeHTTPResponse(
                outbound, allocator: channel.allocator,
                status: 502, reason: "Bad Gateway",
                body: "Cannot connect to \(host):\(port)\n"
            )
            return
        }

        // CIDR check on the resolved IP (catches DNS rebinding to private addresses).
        if let ip = resolvedBlockedIP(channel: remoteChannel.channel, filter: filter) {
            proxyLog.warning("DENY (resolved CIDR) CONNECT \(host):\(port) -> \(ip)")
            try? await remoteChannel.channel.close()
            try await writeHTTPResponse(
                outbound, allocator: channel.allocator,
                status: 403, reason: "Forbidden",
                body: "Blocked: resolved to private IP \(ip)\n"
            )
            return
        }

        // Send 200 Connection Established.
        var response = channel.allocator.buffer(capacity: 39)
        response.writeString("HTTP/1.1 200 Connection Established\r\n\r\n")
        try await outbound.write(response)

        // Switch to bidirectional byte relay.
        try await relay(
            clientIterator: &iterator, clientOutbound: outbound,
            clientChannel: channel, remoteChannel: remoteChannel
        )
    }

    /// Forward a plain HTTP request to the origin server.
    /// One-request-per-connection: Connection: close is injected so the origin server
    /// closes after responding, which naturally terminates the relay.
    private func handleHTTPForward(
        request: HTTPRequest,
        overflow: ByteBuffer,
        iterator: inout NIOAsyncChannelInboundStream<ByteBuffer>.AsyncIterator,
        outbound: NIOAsyncChannelOutboundWriter<ByteBuffer>,
        channel: Channel
    ) async throws {
        let host: String
        let port: Int
        let path: String

        if let components = parseAbsoluteURI(request.uri) {
            host = components.host
            port = components.port ?? 80
            path = components.path
        } else if let hostHeader = request.header("host") {
            let parsed = parseHostPort(hostHeader)
            host = parsed.host
            port = parsed.port ?? 80
            path = request.uri.isEmpty ? "/" : request.uri
        } else {
            try await writeHTTPResponse(
                outbound, allocator: channel.allocator,
                status: 400, reason: "Bad Request", body: "Missing host in request\n"
            )
            return
        }

        let decision = filter.evaluate(host: host, port: port)
        switch decision {
        case .allow:
            proxyLog.info("ALLOW HTTP \(request.method) \(host):\(port)\(path)")
        case let .deny(reason):
            proxyLog.info("DENY HTTP \(request.method) \(host):\(port): \(reason)")
            try await writeHTTPResponse(
                outbound, allocator: channel.allocator,
                status: 403, reason: "Forbidden", body: "Blocked: \(reason)\n"
            )
            return
        }

        // Connect to the origin server.
        let remoteChannel: NIOAsyncChannel<ByteBuffer, ByteBuffer>
        do {
            remoteChannel = try await connectRemote(
                host: host, port: port, group: channel.eventLoop
            )
        } catch {
            proxyLog.error("Failed to connect to \(host):\(port): \(error)")
            try await writeHTTPResponse(
                outbound, allocator: channel.allocator,
                status: 502, reason: "Bad Gateway",
                body: "Cannot connect to \(host):\(port)\n"
            )
            return
        }

        // CIDR check on the resolved IP.
        if let ip = resolvedBlockedIP(channel: remoteChannel.channel, filter: filter) {
            proxyLog.warning("DENY (resolved CIDR) HTTP \(host):\(port) -> \(ip)")
            try? await remoteChannel.channel.close()
            try await writeHTTPResponse(
                outbound, allocator: channel.allocator,
                status: 403, reason: "Forbidden",
                body: "Blocked: resolved to private IP \(ip)\n"
            )
            return
        }

        // Rewrite the request in origin-form and send to remote.
        var raw = "\(request.method) \(path) \(request.version)\r\n"
        for (name, value) in request.headers {
            let lower = name.lowercased()
            // Strip hop-by-hop (RFC 7230 §6.1) headers.
            if lower == "proxy-authorization" || lower == "proxy-connection"
                || lower == "connection" || lower == "te"
                || lower == "keep-alive" || lower == "upgrade" || lower == "trailer"
            { continue }
            // Sanitize to prevent header injection via embedded CRLF.
            let sanitized = value.replacingOccurrences(of: "\r", with: "")
                .replacingOccurrences(of: "\n", with: "")
            raw += "\(name): \(sanitized)\r\n"
        }
        raw += "Connection: close\r\n\r\n"

        // Send the rewritten request headers + any body bytes that arrived
        // in the same read as the headers, then relay the rest.
        var initialToRemote = channel.allocator.buffer(capacity: raw.utf8.count + overflow.readableBytes)
        initialToRemote.writeString(raw)
        if overflow.readableBytes > 0 {
            initialToRemote.writeImmutableBuffer(overflow)
        }

        try await relay(
            clientIterator: &iterator, clientOutbound: outbound,
            clientChannel: channel, remoteChannel: remoteChannel,
            initialToRemote: initialToRemote
        )
    }

    // MARK: - SOCKS5 Proxy Handler

    /// Handle a SOCKS5 connection: greeting, request, tunnel.
    private func handleSOCKS5(
        buffer: inout ByteBuffer,
        iterator: inout NIOAsyncChannelInboundStream<ByteBuffer>.AsyncIterator,
        outbound: NIOAsyncChannelOutboundWriter<ByteBuffer>,
        channel: Channel
    ) async throws {
        // --- Greeting phase ---
        // Accumulate until we have at least 2 bytes (version + numMethods).
        try await accumulate(buffer: &buffer, iterator: &iterator, minimum: 2)
        let base = buffer.readerIndex

        guard let version = buffer.getInteger(at: base, as: UInt8.self),
              let numMethods = buffer.getInteger(at: base + 1, as: UInt8.self)
        else { return }

        guard version == 0x05 else {
            try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x01)
            return
        }

        let greetingLen = 2 + Int(numMethods)
        try await accumulate(buffer: &buffer, iterator: &iterator, minimum: greetingLen)

        // Consume the greeting.
        buffer.moveReaderIndex(forwardBy: greetingLen)

        // Reply: no authentication required [0x05, 0x00].
        var greetReply = channel.allocator.buffer(capacity: 2)
        greetReply.writeInteger(UInt8(0x05))
        greetReply.writeInteger(UInt8(0x00))
        try await outbound.write(greetReply)

        // --- Request phase ---
        try await accumulate(buffer: &buffer, iterator: &iterator, minimum: 4)
        let reqBase = buffer.readerIndex

        guard let reqVersion = buffer.getInteger(at: reqBase, as: UInt8.self),
              let cmd = buffer.getInteger(at: reqBase + 1, as: UInt8.self),
              // byte at reqBase+2 is reserved
              let atyp = buffer.getInteger(at: reqBase + 3, as: UInt8.self)
        else { return }

        guard reqVersion == 0x05 else {
            try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x01)
            return
        }

        // Only CONNECT (0x01) is supported.
        guard cmd == 0x01 else {
            try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x07)
            return
        }

        // Parse address based on type.
        let host: String
        let addrLen: Int

        switch atyp {
        case 0x01: // IPv4: 4 bytes
            try await accumulate(buffer: &buffer, iterator: &iterator, minimum: 4 + 4 + 2)
            let b0 = buffer.getInteger(at: reqBase + 4, as: UInt8.self)!
            let b1 = buffer.getInteger(at: reqBase + 5, as: UInt8.self)!
            let b2 = buffer.getInteger(at: reqBase + 6, as: UInt8.self)!
            let b3 = buffer.getInteger(at: reqBase + 7, as: UInt8.self)!
            host = "\(b0).\(b1).\(b2).\(b3)"
            addrLen = 4

        case 0x03: // Domain name: 1 byte length + name
            try await accumulate(buffer: &buffer, iterator: &iterator, minimum: 5)
            let nameLen = Int(buffer.getInteger(at: reqBase + 4, as: UInt8.self)!)
            guard nameLen > 0 else {
                try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x01)
                return
            }
            try await accumulate(
                buffer: &buffer, iterator: &iterator, minimum: 4 + 1 + nameLen + 2
            )
            guard let nameSlice = buffer.getSlice(at: reqBase + 5, length: nameLen) else {
                try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x01)
                return
            }
            host = String(buffer: nameSlice)
            addrLen = 1 + nameLen

        case 0x04: // IPv6: 16 bytes
            try await accumulate(buffer: &buffer, iterator: &iterator, minimum: 4 + 16 + 2)
            var parts = [String]()
            for i in 0 ..< 8 {
                let word = buffer.getInteger(
                    at: reqBase + 4 + (i * 2), endianness: .big, as: UInt16.self
                )!
                parts.append(String(word, radix: 16))
            }
            host = parts.joined(separator: ":")
            addrLen = 16

        default:
            try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x08)
            return
        }

        // Port (2 bytes, big-endian).
        let portOffset = reqBase + 4 + addrLen
        guard let portBE = buffer.getInteger(
            at: portOffset, endianness: .big, as: UInt16.self
        ) else { return }
        let port = Int(portBE)

        // Consume the request bytes.
        let totalLen = 4 + addrLen + 2
        buffer.moveReaderIndex(forwardBy: totalLen)

        // Domain filter check.
        let decision = filter.evaluate(host: host, port: port)
        switch decision {
        case .allow:
            proxyLog.info("ALLOW SOCKS5 CONNECT \(host):\(port)")
        case let .deny(reason):
            proxyLog.info("DENY SOCKS5 CONNECT \(host):\(port): \(reason)")
            try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x02)
            return
        }

        // --- Tunnel establishment ---
        let remoteChannel: NIOAsyncChannel<ByteBuffer, ByteBuffer>
        do {
            remoteChannel = try await connectRemote(
                host: host, port: port, group: channel.eventLoop
            )
        } catch {
            proxyLog.error("SOCKS5 failed to connect to \(host):\(port): \(error)")
            try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x05)
            return
        }

        // CIDR check on the resolved IP.
        if let ip = resolvedBlockedIP(channel: remoteChannel.channel, filter: filter) {
            proxyLog.warning("DENY (resolved CIDR) SOCKS5 \(host):\(port) -> \(ip)")
            try? await remoteChannel.channel.close()
            try await writeSocks5Error(outbound, allocator: channel.allocator, reply: 0x02)
            return
        }

        // Send success reply.
        var reply = channel.allocator.buffer(capacity: 10)
        reply.writeInteger(UInt8(0x05)) // version
        reply.writeInteger(UInt8(0x00)) // success
        reply.writeInteger(UInt8(0x00)) // reserved
        reply.writeInteger(UInt8(0x01)) // IPv4 address type
        reply.writeInteger(UInt32(0)) // BND.ADDR 0.0.0.0
        reply.writeInteger(UInt16(0)) // BND.PORT 0
        try await outbound.write(reply)

        // Forward any bytes that arrived after the SOCKS5 request
        // (e.g. a TLS ClientHello pipelined immediately).
        let leftover: ByteBuffer? = buffer.readableBytes > 0 ? buffer : nil

        try await relay(
            clientIterator: &iterator, clientOutbound: outbound,
            clientChannel: channel, remoteChannel: remoteChannel,
            initialToRemote: leftover
        )
    }

    // MARK: - Bidirectional Relay

    /// Relay raw bytes between client and remote channels.
    /// Client-to-remote runs on the current task (owns the inout iterator).
    /// Remote-to-client runs in a child task (remoteInbound is Sendable).
    /// When either side closes, the other is closed to tear down the relay.
    private func relay(
        clientIterator: inout NIOAsyncChannelInboundStream<ByteBuffer>.AsyncIterator,
        clientOutbound: NIOAsyncChannelOutboundWriter<ByteBuffer>,
        clientChannel: Channel,
        remoteChannel: NIOAsyncChannel<ByteBuffer, ByteBuffer>,
        initialToRemote: ByteBuffer? = nil
    ) async throws {
        try await remoteChannel.executeThenClose { remoteInbound, remoteOutbound in
            // Forward any bytes that were buffered during handshake/header parsing.
            if let initial = initialToRemote {
                try await remoteOutbound.write(initial)
            }
            try await withThrowingTaskGroup(of: Void.self) { group in
                // remote -> client in a child task (remoteInbound is Sendable).
                group.addTask { [clientChannel] in
                    for try await buf in remoteInbound {
                        try await clientOutbound.write(buf)
                    }
                    // Remote closed — close client channel to unblock the iterator.
                    try? await clientChannel.close()
                }
                // client -> remote on THIS task (inout iterator, no @Sendable capture).
                while let buf = try await clientIterator.next() {
                    try await remoteOutbound.write(buf)
                }
                // Client side closed -> cancel remote->client task.
                group.cancelAll()
            }
        }
    }

    // MARK: - Remote Connection

    /// Connect to a remote host and return a typed async channel.
    private func connectRemote(
        host: String, port: Int, group: EventLoopGroup
    ) async throws -> NIOAsyncChannel<ByteBuffer, ByteBuffer> {
        try await ClientBootstrap(group: group)
            .connect(host: host, port: port) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try NIOAsyncChannel<ByteBuffer, ByteBuffer>(
                        wrappingChannelSynchronously: channel
                    )
                }
            }
    }

    // MARK: - HTTP Helpers

    /// Write an HTTP response as raw bytes.
    private func writeHTTPResponse(
        _ outbound: NIOAsyncChannelOutboundWriter<ByteBuffer>,
        allocator: ByteBufferAllocator,
        status: Int, reason: String, body: String
    ) async throws {
        var buf = allocator.buffer(capacity: 256)
        buf.writeString("HTTP/1.1 \(status) \(reason)\r\n")
        buf.writeString("Content-Type: text/plain\r\n")
        buf.writeString("Content-Length: \(body.utf8.count)\r\n")
        buf.writeString("Connection: close\r\n\r\n")
        buf.writeString(body)
        try await outbound.write(buf)
    }

    private func parseConnectTarget(_ target: String) -> (host: String, port: Int) {
        let (host, port) = parseHostPort(target)
        return (host, port ?? 443)
    }

    /// Parse an absolute-form URI (e.g. "http://host:port/path?query") into components.
    private func parseAbsoluteURI(_ uri: String) -> (host: String, port: Int?, path: String)? {
        guard uri.lowercased().hasPrefix("http://") else { return nil }
        let withoutScheme = String(uri.dropFirst("http://".count))
        let slashIndex = withoutScheme.firstIndex(of: "/") ?? withoutScheme.endIndex
        let authority = String(withoutScheme[..<slashIndex])
        let path = slashIndex < withoutScheme.endIndex
            ? String(withoutScheme[slashIndex...]) : "/"
        let (host, port) = parseHostPort(authority)
        guard !host.isEmpty else { return nil }
        return (host, port, path)
    }

    // MARK: - SOCKS5 Helpers

    /// Write a SOCKS5 error reply and close.
    private func writeSocks5Error(
        _ outbound: NIOAsyncChannelOutboundWriter<ByteBuffer>,
        allocator: ByteBufferAllocator,
        reply: UInt8
    ) async throws {
        var buf = allocator.buffer(capacity: 10)
        buf.writeInteger(UInt8(0x05)) // version
        buf.writeInteger(reply)
        buf.writeInteger(UInt8(0x00)) // reserved
        buf.writeInteger(UInt8(0x01)) // IPv4
        buf.writeInteger(UInt32(0)) // 0.0.0.0
        buf.writeInteger(UInt16(0)) // port 0
        try await outbound.write(buf)
    }
}

// MARK: - HTTP Request Parser

/// A parsed HTTP request (request line + headers only).
private struct HTTPRequest {
    var method: String
    var uri: String
    var version: String
    var headers: [(name: String, value: String)]

    /// Look up the first header value matching the given name (case-insensitive).
    func header(_ name: String) -> String? {
        let lower = name.lowercased()
        return headers.first { $0.name.lowercased() == lower }?.value
    }
}

/// Maximum bytes to buffer while parsing HTTP request headers.
private let maxHTTPHeaderSize = 8192

/// Parse an HTTP request from the buffer, accumulating more data from the iterator as needed.
/// On return, `buffer` contains only the overflow bytes (body data after headers).
private func parseHTTPRequest(
    buffer: inout ByteBuffer,
    iterator: inout NIOAsyncChannelInboundStream<ByteBuffer>.AsyncIterator
) async throws -> HTTPRequest {
    // Accumulate until we find \r\n\r\n marking end of headers.
    while true {
        if let separatorRange = findHeaderEnd(in: buffer) {
            let headerBytes = buffer.readSlice(length: separatorRange)!
            // Skip past the \r\n\r\n separator.
            buffer.moveReaderIndex(forwardBy: 4)
            // buffer now contains only overflow (body bytes).
            return try parseRequestBytes(headerBytes)
        }

        guard buffer.readableBytes < maxHTTPHeaderSize else {
            throw ProxyError.headersTooLarge
        }

        guard let next = try await iterator.next() else {
            throw ProxyError.connectionClosed
        }
        buffer.writeImmutableBuffer(next)
    }
}

/// Find the byte offset (from readerIndex) of the start of \r\n\r\n in the buffer.
/// Returns nil if not found.
private func findHeaderEnd(in buffer: ByteBuffer) -> Int? {
    let readable = buffer.readableBytes
    guard readable >= 4 else { return nil }
    let base = buffer.readerIndex
    for i in 0 ... (readable - 4) {
        if buffer.getInteger(at: base + i, as: UInt8.self) == 0x0D, // \r
           buffer.getInteger(at: base + i + 1, as: UInt8.self) == 0x0A, // \n
           buffer.getInteger(at: base + i + 2, as: UInt8.self) == 0x0D, // \r
           buffer.getInteger(at: base + i + 3, as: UInt8.self) == 0x0A // \n
        {
            return i
        }
    }
    return nil
}

/// Parse raw header bytes into an HTTPRequest.
private func parseRequestBytes(_ buffer: ByteBuffer) throws -> HTTPRequest {
    guard let text = buffer.getString(at: buffer.readerIndex, length: buffer.readableBytes) else {
        throw ProxyError.malformedRequest
    }

    var lines = text.split(separator: "\r\n", omittingEmptySubsequences: false)
    guard !lines.isEmpty else { throw ProxyError.malformedRequest }

    // Request line: "METHOD URI HTTP/1.1"
    let requestLine = lines.removeFirst()
    let parts = requestLine.split(separator: " ", maxSplits: 2)
    guard parts.count == 3 else { throw ProxyError.malformedRequest }

    let method = String(parts[0])
    let uri = String(parts[1])
    let version = String(parts[2])

    // Headers
    var headers: [(name: String, value: String)] = []
    for line in lines {
        if line.isEmpty { break }
        guard let colonIndex = line.firstIndex(of: ":") else { continue }
        let name = String(line[line.startIndex ..< colonIndex]).trimmingCharacters(in: .whitespaces)
        let value = String(line[line.index(after: colonIndex)...]).trimmingCharacters(
            in: .whitespaces
        )
        headers.append((name: name, value: value))
    }

    return HTTPRequest(method: method, uri: uri, version: version, headers: headers)
}

// MARK: - Buffer Accumulation

/// Maximum bytes to buffer during SOCKS5 handshake.
private let maxHandshakeBuffer = 1024

/// Ensure the buffer has at least `minimum` readable bytes by reading from the iterator.
private func accumulate(
    buffer: inout ByteBuffer,
    iterator: inout NIOAsyncChannelInboundStream<ByteBuffer>.AsyncIterator,
    minimum: Int
) async throws {
    while buffer.readableBytes < minimum {
        guard buffer.readableBytes < maxHandshakeBuffer else {
            throw ProxyError.handshakeTooLarge
        }
        guard let next = try await iterator.next() else {
            throw ProxyError.connectionClosed
        }
        buffer.writeImmutableBuffer(next)
    }
}

// MARK: - Shared CIDR Check

/// Extract the resolved IP from a connected channel and check it against blocked CIDRs.
/// Returns the blocked IP string if blocked, nil if allowed.
private func resolvedBlockedIP(channel: Channel, filter: DomainFilter) -> String? {
    let resolvedIP: String?
    switch channel.remoteAddress {
    case let .v4(addr): resolvedIP = addr.host
    case let .v6(addr): resolvedIP = addr.host
    default: resolvedIP = nil
    }
    guard let ip = resolvedIP, filter.isBlockedCIDR(ip) else { return nil }
    return ip
}

// MARK: - Errors

private enum ProxyError: Error {
    case headersTooLarge
    case handshakeTooLarge
    case malformedRequest
    case connectionClosed
}
