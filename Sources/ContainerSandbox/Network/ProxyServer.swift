import Foundation
import Logging
@preconcurrency import NIOCore
@preconcurrency import NIOHTTP1
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

            let bootstrap = ServerBootstrap(group: group)
                .serverChannelOption(.backlog, value: 256)
                .childChannelInitializer { channel in
                    channel.pipeline.addHandler(ProtocolDetectionHandler(filter: self.filter))
                }
                .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

            // Socket lives inside a 0o700 directory created by ProxyManager — directory
            // permissions gate access, so no chmod needed here.
            let channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
            proxyLog.info("Proxy listening on \(socketPath)")

            try await channel.closeFuture.get()
            try await group.shutdownGracefully()
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

// MARK: - Protocol Detection Handler

/// Inspects the first byte of a new connection to determine HTTP vs SOCKS5,
/// then installs the appropriate handler pipeline and replays the buffered data.
private final class ProtocolDetectionHandler: ChannelInboundHandler, RemovableChannelHandler,
    @unchecked Sendable
{
    typealias InboundIn = ByteBuffer

    let filter: DomainFilter

    init(filter: DomainFilter) {
        self.filter = filter
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)

        guard let firstByte = buffer.getInteger(at: buffer.readerIndex, as: UInt8.self) else {
            context.close(promise: nil)
            return
        }

        let pipeline = context.channel.pipeline

        if firstByte == 0x05 {
            // SOCKS5 greeting always starts with version byte 0x05.
            pipeline.removeHandler(self).flatMap {
                pipeline.addHandler(Socks5ProxyHandler(filter: self.filter))
            }.whenComplete { result in
                if case let .failure(error) = result {
                    proxyLog.error("Failed to install SOCKS5 pipeline: \(error)")
                    context.close(promise: nil)
                    return
                }
                pipeline.fireChannelRead(data)
            }
        } else {
            // Anything else is HTTP (CONNECT for HTTPS tunneling, or plain HTTP).
            pipeline.removeHandler(self).flatMap {
                pipeline.addHandler(
                    ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
                )
            }.flatMap {
                pipeline.addHandler(HTTPResponseEncoder())
            }.flatMap {
                pipeline.addHandler(ConnectProxyHandler(filter: self.filter))
            }.whenComplete { result in
                if case let .failure(error) = result {
                    proxyLog.error("Failed to install HTTP pipeline: \(error)")
                    context.close(promise: nil)
                    return
                }
                pipeline.fireChannelRead(data)
            }
        }
    }
}

// MARK: - HTTP Proxy Handler (CONNECT + Forward)

/// Handles HTTP CONNECT requests for HTTPS tunneling and plain HTTP forward proxying.
/// NIO channel handlers are confined to their event loop; @unchecked Sendable is standard practice.
private final class ConnectProxyHandler: ChannelInboundHandler, RemovableChannelHandler,
    @unchecked Sendable
{
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let filter: DomainFilter
    private var requestHead: HTTPRequestHead?

    // Plain HTTP streaming state. Body chunks are queued while connecting to the
    // origin server, then forwarded directly once connected.
    private var remoteChannel: Channel? // Set once connected to origin
    private var bodyBuffer: [ByteBuffer]? // Non-nil while connecting (queuing chunks)
    private var endReceived = false // .end arrived while still connecting
    private var useChunked = false // Re-chunking body to origin
    private var originPath: String?

    init(filter: DomainFilter) {
        self.filter = filter
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case let .head(head):
            requestHead = head
            if head.method == .CONNECT {
                handleConnect(context: context, head: head)
            } else {
                startHTTPForward(context: context, head: head)
            }

        case let .body(bodyData):
            // CONNECT has no body; only forward for plain HTTP.
            guard requestHead?.method != .CONNECT else { break }
            if let remote = remoteChannel {
                writeBodyChunk(bodyData, to: remote, allocator: context.channel.allocator)
                remote.flush()
            } else {
                bodyBuffer?.append(bodyData)
            }

        case .end:
            guard let head = requestHead, head.method != .CONNECT else { break }
            _ = head
            if let remote = remoteChannel {
                finishHTTPForward(context: context, remoteChannel: remote)
            } else {
                // Still connecting — httpConnected will finish when the connection lands.
                // Don't nil requestHead yet; httpConnected needs it for the headers.
                endReceived = true
            }
        }
    }

    // MARK: - CONNECT (HTTPS tunneling)

    /// Handle CONNECT method — extract host:port, check filter, tunnel or reject.
    private func handleConnect(context: ChannelHandlerContext, head: HTTPRequestHead) {
        let target = head.uri // host:port
        let (host, port) = parseTarget(target)

        let decision = filter.evaluate(host: host, port: port)
        switch decision {
        case .allow:
            proxyLog.info("ALLOW CONNECT \(target)")
            // CIDR check happens post-connect on the resolved IP (in establishTunnel)
            // to catch both literal IPs and DNS rebinding to private addresses.
            establishTunnel(context: context, host: host, port: port)
        case let .deny(reason):
            proxyLog.info("DENY CONNECT \(target): \(reason)")
            sendResponse(context: context, status: .forbidden, body: "Blocked: \(reason)\n")
        }
    }

    /// Establish a TCP tunnel to the target host.
    /// Post-connect: checks the resolved IP against blocked CIDRs before sending 200.
    private func establishTunnel(context: ChannelHandlerContext, host: String, port: Int) {
        ClientBootstrap(group: context.eventLoop)
            .connect(host: host, port: port)
            .whenComplete { result in
                switch result {
                case let .success(remoteChannel):
                    // Check resolved IP against blocked CIDRs (catches DNS rebinding).
                    if self.checkCIDRAndReject(
                        context: context, remoteChannel: remoteChannel,
                        protocol: "CONNECT", host: host, port: port
                    ) { return }
                    self.tunnelEstablished(context: context, remoteChannel: remoteChannel)
                case let .failure(error):
                    proxyLog.error("Failed to connect to \(host):\(port): \(error)")
                    self.sendResponse(
                        context: context, status: .badGateway,
                        body: "Cannot connect to \(host):\(port)\n"
                    )
                }
            }
    }

    /// Tunnel is established — send 200, then switch to raw byte relay.
    private func tunnelEstablished(context: ChannelHandlerContext, remoteChannel: Channel) {
        // Send 200 Connection Established with content-length: 0 to prevent
        // HTTPResponseEncoder from adding transfer-encoding: chunked and its
        // terminator bytes, which would corrupt the subsequent TLS handshake.
        var head = HTTPResponseHead(version: .http1_1, status: .ok)
        head.headers.add(name: "content-length", value: "0")
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)

        switchToRelay(context: context, remoteChannel: remoteChannel)
    }

    // MARK: - Plain HTTP forward proxy (streaming)

    /// Begin forwarding a plain HTTP request: parse host, check filter, connect to origin.
    /// Body chunks are queued during connection and forwarded once connected.
    /// One-request-per-connection: Connection: close is injected so the origin server
    /// closes after responding, which triggers ByteRelayHandler.channelInactive to tear
    /// down both sides.
    private func startHTTPForward(context: ChannelHandlerContext, head: HTTPRequestHead) {
        let host: String
        let port: Int
        let path: String

        if let components = parseAbsoluteURI(head.uri) {
            host = components.host
            port = components.port ?? 80
            path = components.path
        } else if let hostHeader = head.headers["host"].first {
            let parsed = parseHostPort(hostHeader)
            host = parsed.host
            port = parsed.port ?? 80
            path = head.uri.isEmpty ? "/" : head.uri
        } else {
            sendResponse(context: context, status: .badRequest, body: "Missing host in request\n")
            return
        }

        let decision = filter.evaluate(host: host, port: port)
        switch decision {
        case .allow:
            proxyLog.info("ALLOW HTTP \(head.method) \(host):\(port)\(path)")
        case let .deny(reason):
            proxyLog.info("DENY HTTP \(head.method) \(host):\(port): \(reason)")
            sendResponse(context: context, status: .forbidden, body: "Blocked: \(reason)\n")
            return
        }

        originPath = path
        bodyBuffer = []
        endReceived = false

        // If the original request has Content-Length, forward it and stream raw bytes.
        // If it was chunked (NIO de-chunks the body but preserves the header), re-chunk.
        useChunked = !head.headers.contains(name: "content-length")
            && head.headers["transfer-encoding"].contains { $0.lowercased().contains("chunked") }

        ClientBootstrap(group: context.eventLoop)
            .connect(host: host, port: port)
            .whenComplete { result in
                switch result {
                case let .success(remote):
                    if self.checkCIDRAndReject(
                        context: context, remoteChannel: remote,
                        protocol: "HTTP", host: host, port: port
                    ) {
                        self.resetHTTPState()
                        return
                    }
                    self.httpConnected(context: context, remote: remote)

                case let .failure(error):
                    proxyLog.error("Failed to connect to \(host):\(port): \(error)")
                    self.sendResponse(
                        context: context, status: .badGateway,
                        body: "Cannot connect to \(host):\(port)\n"
                    )
                    self.resetHTTPState()
                }
            }
    }

    /// Origin connected — write request headers, flush queued body, enter forwarding state.
    private func httpConnected(context: ChannelHandlerContext, remote: Channel) {
        guard let head = requestHead, let path = originPath else { return }

        // Build request line + headers in origin-form.
        var raw = "\(head.method) \(path) HTTP/\(head.version.major).\(head.version.minor)\r\n"
        for (name, value) in head.headers {
            let lower = name.lowercased()
            // Strip hop-by-hop (RFC 7230 §6.1) and framing headers.
            if lower == "proxy-authorization" || lower == "proxy-connection"
                || lower == "connection" || lower == "transfer-encoding"
                || lower == "content-length" || lower == "te"
                || lower == "keep-alive" || lower == "upgrade" || lower == "trailer"
            { continue }
            // Sanitize to prevent header injection via embedded CRLF.
            let sanitized = value.replacingOccurrences(of: "\r", with: "")
                .replacingOccurrences(of: "\n", with: "")
            raw += "\(name): \(sanitized)\r\n"
        }
        if let cl = head.headers["content-length"].first {
            raw += "Content-Length: \(cl)\r\n"
        } else if useChunked {
            raw += "Transfer-Encoding: chunked\r\n"
        }
        raw += "Connection: close\r\n\r\n"

        var buf = context.channel.allocator.buffer(capacity: raw.utf8.count)
        buf.writeString(raw)
        remote.write(buf, promise: nil)

        // Flush any body chunks that arrived while connecting.
        if let buffered = bodyBuffer {
            for chunk in buffered {
                writeBodyChunk(chunk, to: remote, allocator: context.channel.allocator)
            }
        }

        // Switch from buffering to direct forwarding.
        remoteChannel = remote
        bodyBuffer = nil

        if endReceived {
            finishHTTPForward(context: context, remoteChannel: remote)
        } else {
            remote.flush()
        }
    }

    /// Write a single body chunk to the origin (raw or chunked-encoded).
    private func writeBodyChunk(_ data: ByteBuffer, to channel: Channel, allocator: ByteBufferAllocator) {
        guard data.readableBytes > 0 else { return }
        if useChunked {
            var header = allocator.buffer(capacity: 16)
            header.writeString(String(data.readableBytes, radix: 16))
            header.writeString("\r\n")
            channel.write(header, promise: nil)
            channel.write(data, promise: nil)
            var trailer = allocator.buffer(capacity: 2)
            trailer.writeString("\r\n")
            channel.write(trailer, promise: nil)
        } else {
            channel.write(data, promise: nil)
        }
    }

    /// Request complete — write chunked terminator if needed, switch to byte relay.
    private func finishHTTPForward(context: ChannelHandlerContext, remoteChannel: Channel) {
        if useChunked {
            var terminator = context.channel.allocator.buffer(capacity: 5)
            terminator.writeString("0\r\n\r\n")
            remoteChannel.writeAndFlush(terminator, promise: nil)
        } else {
            remoteChannel.flush()
        }
        switchToRelay(context: context, remoteChannel: remoteChannel)
        resetHTTPState()
    }

    private func resetHTTPState() {
        requestHead = nil
        remoteChannel = nil
        bodyBuffer = nil
        endReceived = false
        useChunked = false
        originPath = nil
    }

    // MARK: - Shared helpers

    /// Remove HTTP handlers from the client pipeline and install ByteRelayHandlers
    /// on both client and remote channels.
    private func switchToRelay(context: ChannelHandlerContext, remoteChannel: Channel) {
        let clientChannel = context.channel
        let pipeline = clientChannel.pipeline

        pipeline.removeHandler(self).flatMap {
            pipeline.handler(type: HTTPResponseEncoder.self)
        }.flatMap { encoder in
            pipeline.removeHandler(encoder)
        }.flatMap {
            pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
        }.flatMap { decoder in
            pipeline.removeHandler(decoder)
        }.flatMap {
            pipeline.addHandler(ByteRelayHandler(partner: remoteChannel))
        }.flatMap { _ in
            remoteChannel.pipeline.addHandler(ByteRelayHandler(partner: clientChannel))
        }.whenComplete { result in
            if case let .failure(error) = result {
                proxyLog.error("Failed to switch to relay: \(error)")
                clientChannel.close(promise: nil)
                remoteChannel.close(promise: nil)
                return
            }
            clientChannel.read()
            remoteChannel.read()
        }
    }

    /// Check the resolved IP of a remote channel against blocked CIDRs.
    /// If blocked, closes the remote channel, sends 403, and returns true.
    @discardableResult
    private func checkCIDRAndReject(
        context: ChannelHandlerContext,
        remoteChannel: Channel,
        protocol proto: String,
        host: String,
        port: Int
    ) -> Bool {
        if let ip = resolvedBlockedIP(remoteChannel: remoteChannel, filter: filter) {
            proxyLog.warning("DENY (resolved CIDR) \(proto) \(host):\(port) -> \(ip)")
            remoteChannel.close(promise: nil)
            sendResponse(
                context: context, status: .forbidden,
                body: "Blocked: resolved to private IP \(ip)\n"
            )
            return true
        }
        return false
    }

    private func sendResponse(
        context: ChannelHandlerContext, status: HTTPResponseStatus, body: String
    ) {
        var headers = HTTPHeaders()
        headers.add(name: "content-type", value: "text/plain")
        headers.add(name: "connection", value: "close")
        let head = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)

        var buffer = context.channel.allocator.buffer(capacity: body.utf8.count)
        buffer.writeString(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)

        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            context.close(promise: nil)
        }
    }

    private func parseTarget(_ target: String) -> (host: String, port: Int) {
        let (host, port) = parseHostPort(target)
        return (host, port ?? 443)
    }

    /// Parse an absolute-form URI (e.g. "http://host:port/path?query") into components.
    private func parseAbsoluteURI(_ uri: String) -> (host: String, port: Int?, path: String)? {
        guard uri.lowercased().hasPrefix("http://") else { return nil }
        let withoutScheme = String(uri.dropFirst("http://".count))
        let slashIndex = withoutScheme.firstIndex(of: "/") ?? withoutScheme.endIndex
        let authority = String(withoutScheme[..<slashIndex])
        let path = slashIndex < withoutScheme.endIndex ? String(withoutScheme[slashIndex...]) : "/"
        let (host, port) = parseHostPort(authority)
        guard !host.isEmpty else { return nil }
        return (host, port, path)
    }
}

// MARK: - SOCKS5 Proxy Handler

/// Handles SOCKS5 protocol (RFC 1928) for arbitrary TCP tunneling.
/// Only supports the CONNECT command with no authentication.
private final class Socks5ProxyHandler: ChannelInboundHandler, RemovableChannelHandler,
    @unchecked Sendable
{
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum State {
        case awaitingGreeting
        case awaitingRequest
    }

    let filter: DomainFilter
    private var state: State = .awaitingGreeting
    private var buffer: ByteBuffer?

    init(filter: DomainFilter) {
        self.filter = filter
    }

    /// Maximum bytes to buffer during SOCKS5 handshake. Valid handshakes are
    /// always under 300 bytes; anything beyond this is a misbehaving client.
    private static let maxHandshakeBuffer = 1024

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)

        if buffer != nil {
            buffer!.writeBuffer(&incoming)
        } else {
            buffer = incoming
        }

        if let buf = buffer, buf.readableBytes > Self.maxHandshakeBuffer {
            proxyLog.warning("SOCKS5 handshake buffer exceeded \(Self.maxHandshakeBuffer) bytes")
            context.close(promise: nil)
            return
        }

        switch state {
        case .awaitingGreeting:
            handleGreeting(context: context)
        case .awaitingRequest:
            handleRequest(context: context)
        }
    }

    // MARK: - Greeting phase

    private func handleGreeting(context: ChannelHandlerContext) {
        guard let buf = buffer, buf.readableBytes >= 2 else { return }
        let base = buf.readerIndex

        guard let version = buf.getInteger(at: base, as: UInt8.self),
              let numMethods = buf.getInteger(at: base + 1, as: UInt8.self)
        else { return }

        guard version == 0x05 else {
            sendError(context: context, reply: 0x01)
            return
        }

        let needed = 2 + Int(numMethods)
        guard buf.readableBytes >= needed else { return }

        // Consume the greeting.
        buffer!.moveReaderIndex(forwardBy: needed)
        if buffer!.readableBytes == 0 { buffer = nil }

        // Reply: no authentication required [0x05, 0x00].
        var reply = context.channel.allocator.buffer(capacity: 2)
        reply.writeInteger(UInt8(0x05))
        reply.writeInteger(UInt8(0x00))
        context.writeAndFlush(wrapOutboundOut(reply), promise: nil)

        state = .awaitingRequest

        // If more data was already buffered (request pipelined with greeting), process it.
        if buffer != nil {
            handleRequest(context: context)
        }
    }

    // MARK: - Request phase

    private func handleRequest(context: ChannelHandlerContext) {
        guard let buf = buffer, buf.readableBytes >= 4 else { return }
        let base = buf.readerIndex

        guard let version = buf.getInteger(at: base, as: UInt8.self),
              let cmd = buf.getInteger(at: base + 1, as: UInt8.self),
              // byte at base+2 is reserved
              let atyp = buf.getInteger(at: base + 3, as: UInt8.self)
        else { return }

        guard version == 0x05 else {
            sendError(context: context, reply: 0x01)
            return
        }

        // Only CONNECT (0x01) is supported.
        guard cmd == 0x01 else {
            sendError(context: context, reply: 0x07) // Command not supported
            return
        }

        // Parse address based on type.
        let host: String
        let addrLen: Int

        switch atyp {
        case 0x01: // IPv4: 4 bytes
            guard buf.readableBytes >= 4 + 4 + 2 else { return }
            let b0 = buf.getInteger(at: base + 4, as: UInt8.self)!
            let b1 = buf.getInteger(at: base + 5, as: UInt8.self)!
            let b2 = buf.getInteger(at: base + 6, as: UInt8.self)!
            let b3 = buf.getInteger(at: base + 7, as: UInt8.self)!
            host = "\(b0).\(b1).\(b2).\(b3)"
            addrLen = 4

        case 0x03: // Domain name: 1 byte length + name
            guard buf.readableBytes >= 5 else { return }
            let nameLen = Int(buf.getInteger(at: base + 4, as: UInt8.self)!)
            guard nameLen > 0, buf.readableBytes >= 4 + 1 + nameLen + 2 else { return }
            guard let nameSlice = buf.getSlice(at: base + 5, length: nameLen) else {
                sendError(context: context, reply: 0x01)
                return
            }
            host = String(buffer: nameSlice)
            addrLen = 1 + nameLen

        case 0x04: // IPv6: 16 bytes
            guard buf.readableBytes >= 4 + 16 + 2 else { return }
            var parts = [String]()
            for i in 0 ..< 8 {
                let word = buf.getInteger(
                    at: base + 4 + (i * 2), endianness: .big, as: UInt16.self
                )!
                parts.append(String(word, radix: 16))
            }
            host = parts.joined(separator: ":")
            addrLen = 16

        default:
            sendError(context: context, reply: 0x08) // Address type not supported
            return
        }

        // Port (2 bytes, big-endian).
        let portOffset = base + 4 + addrLen
        guard let portBE = buf.getInteger(at: portOffset, endianness: .big, as: UInt16.self) else {
            return
        }
        let port = Int(portBE)

        // Consume the request bytes.
        let totalLen = 4 + addrLen + 2
        buffer!.moveReaderIndex(forwardBy: totalLen)
        if buffer!.readableBytes == 0 { buffer = nil }

        // Domain filter check.
        let decision = filter.evaluate(host: host, port: port)
        switch decision {
        case .allow:
            proxyLog.info("ALLOW SOCKS5 CONNECT \(host):\(port)")
            establishTunnel(context: context, host: host, port: port)
        case let .deny(reason):
            proxyLog.info("DENY SOCKS5 CONNECT \(host):\(port): \(reason)")
            sendError(context: context, reply: 0x02) // Connection not allowed by ruleset
        }
    }

    // MARK: - Tunnel establishment

    private func establishTunnel(context: ChannelHandlerContext, host: String, port: Int) {
        ClientBootstrap(group: context.eventLoop)
            .connect(host: host, port: port)
            .whenComplete { result in
                switch result {
                case let .success(remoteChannel):
                    if let ip = resolvedBlockedIP(
                        remoteChannel: remoteChannel, filter: self.filter
                    ) {
                        proxyLog.warning(
                            "DENY (resolved CIDR) SOCKS5 \(host):\(port) -> \(ip)"
                        )
                        remoteChannel.close(promise: nil)
                        self.sendError(context: context, reply: 0x02)
                        return
                    }

                    // Send success reply before switching to relay.
                    var reply = context.channel.allocator.buffer(capacity: 10)
                    reply.writeInteger(UInt8(0x05)) // version
                    reply.writeInteger(UInt8(0x00)) // success
                    reply.writeInteger(UInt8(0x00)) // reserved
                    reply.writeInteger(UInt8(0x01)) // IPv4 address type
                    reply.writeInteger(UInt32(0)) // BND.ADDR 0.0.0.0
                    reply.writeInteger(UInt16(0)) // BND.PORT 0
                    context.writeAndFlush(self.wrapOutboundOut(reply), promise: nil)

                    // Switch to byte relay.
                    let clientChannel = context.channel
                    let pipeline = clientChannel.pipeline
                    let leftover = self.buffer
                    self.buffer = nil

                    pipeline.removeHandler(self).flatMap {
                        pipeline.addHandler(ByteRelayHandler(partner: remoteChannel))
                    }.flatMap { _ in
                        remoteChannel.pipeline.addHandler(
                            ByteRelayHandler(partner: clientChannel)
                        )
                    }.whenComplete { result in
                        if case let .failure(error) = result {
                            proxyLog.error("SOCKS5 failed to switch to relay: \(error)")
                            clientChannel.close(promise: nil)
                            remoteChannel.close(promise: nil)
                            return
                        }
                        // Forward any bytes that arrived after the SOCKS5 request
                        // (e.g. a TLS ClientHello pipelined immediately).
                        if let leftover = leftover {
                            remoteChannel.writeAndFlush(leftover, promise: nil)
                        }
                        clientChannel.read()
                        remoteChannel.read()
                    }

                case let .failure(error):
                    proxyLog.error("SOCKS5 failed to connect to \(host):\(port): \(error)")
                    self.sendError(context: context, reply: 0x05) // Connection refused
                }
            }
    }

    // MARK: - Error reply

    private func sendError(context: ChannelHandlerContext, reply: UInt8) {
        var buf = context.channel.allocator.buffer(capacity: 10)
        buf.writeInteger(UInt8(0x05)) // version
        buf.writeInteger(reply)
        buf.writeInteger(UInt8(0x00)) // reserved
        buf.writeInteger(UInt8(0x01)) // IPv4
        buf.writeInteger(UInt32(0)) // 0.0.0.0
        buf.writeInteger(UInt16(0)) // port 0
        context.writeAndFlush(wrapOutboundOut(buf)).whenComplete { _ in
            context.close(promise: nil)
        }
    }
}

// MARK: - Shared CIDR Check

/// Extract the resolved IP from a connected channel and check it against blocked CIDRs.
/// Returns the blocked IP string if blocked, nil if allowed.
private func resolvedBlockedIP(remoteChannel: Channel, filter: DomainFilter) -> String? {
    let resolvedIP: String?
    switch remoteChannel.remoteAddress {
    case let .v4(addr): resolvedIP = addr.host
    case let .v6(addr): resolvedIP = addr.host
    default: resolvedIP = nil
    }
    guard let ip = resolvedIP, filter.isBlockedCIDR(ip) else { return nil }
    return ip
}

// MARK: - Byte Relay Handler

/// Relays raw bytes between two channels (bidirectional tunnel).
private final class ByteRelayHandler: ChannelInboundHandler, RemovableChannelHandler,
    @unchecked Sendable
{
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    let partner: Channel

    init(partner: Channel) {
        self.partner = partner
    }

    func channelRead(context _: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)
        partner.writeAndFlush(buffer, promise: nil)
    }

    func channelInactive(context _: ChannelHandlerContext) {
        partner.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error _: Error) {
        context.close(promise: nil)
    }
}
