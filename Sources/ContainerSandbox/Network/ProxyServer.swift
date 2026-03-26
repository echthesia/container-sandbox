import Foundation
import Logging
@preconcurrency import NIOCore
@preconcurrency import NIOHTTP1
import NIOPosix

private let proxyLog = Logger(label: "container-sandbox.proxy")

/// An HTTP CONNECT proxy that listens on a Unix domain socket.
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
        defer {
            // shutdownGracefully is a void async function; call from a detached task.
            let g = group
            Task.detached { try? await g.shutdownGracefully() }
        }

        // Remove stale socket file if present.
        unlink(socketPath)

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)))
                    .flatMap {
                        channel.pipeline.addHandler(HTTPResponseEncoder())
                    }
                    .flatMap {
                        channel.pipeline.addHandler(ConnectProxyHandler(filter: self.filter))
                    }
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

        let channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
        proxyLog.info("Proxy listening on \(socketPath)")

        // Owner-only access — both proxy and framework run as the same user.
        chmod(socketPath, 0o600)

        try await channel.closeFuture.get()
    }
}

// MARK: - CONNECT Proxy Handler

/// Handles HTTP CONNECT requests for HTTPS tunneling and plain HTTP forwarding.
// NIO channel handlers are confined to their event loop; @unchecked Sendable is standard practice.
private final class ConnectProxyHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let filter: DomainFilter
    private var requestHead: HTTPRequestHead?

    init(filter: DomainFilter) {
        self.filter = filter
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case .head(let head):
            requestHead = head
            if head.method == .CONNECT {
                handleConnect(context: context, head: head)
            }
        case .body:
            break
        case .end:
            if let head = requestHead, head.method != .CONNECT {
                handlePlainHTTP(context: context, head: head)
            }
            requestHead = nil
        }
    }

    /// Handle CONNECT method — extract host:port, check filter, tunnel or reject.
    private func handleConnect(context: ChannelHandlerContext, head: HTTPRequestHead) {
        let target = head.uri // host:port
        let (host, port) = parseTarget(target)

        let decision = filter.evaluate(host: host, port: port)
        switch decision {
        case .allow:
            if filter.isBlockedCIDR(host) {
                proxyLog.warning("DENY (CIDR) CONNECT \(target)")
                sendResponse(context: context, status: .forbidden, body: "Blocked by CIDR policy: \(target)\n")
                return
            }
            proxyLog.info("ALLOW CONNECT \(target)")
            establishTunnel(context: context, host: host, port: port)
        case .deny(let reason):
            proxyLog.info("DENY CONNECT \(target): \(reason)")
            sendResponse(context: context, status: .forbidden, body: "Blocked: \(reason)\n")
        }
    }

    /// Handle plain HTTP request — check host, reject (we don't forward plain HTTP for now).
    private func handlePlainHTTP(context: ChannelHandlerContext, head: HTTPRequestHead) {
        let host = head.headers["host"].first ?? "unknown"
        proxyLog.info("DENY plain HTTP to \(host) (only CONNECT supported)")
        sendResponse(context: context, status: .forbidden, body: "Plain HTTP not supported; use HTTPS\n")
    }

    /// Establish a TCP tunnel to the target host.
    /// Post-connect: checks the resolved IP against blocked CIDRs before sending 200.
    private func establishTunnel(context: ChannelHandlerContext, host: String, port: Int) {
        let group = context.eventLoop

        ClientBootstrap(group: group)
            .connect(host: host, port: port)
            .whenComplete { result in
                switch result {
                case .success(let remoteChannel):
                    // Check resolved IP against blocked CIDRs (catches DNS rebinding).
                    let resolvedIP: String?
                    switch remoteChannel.remoteAddress {
                    case .v4(let addr): resolvedIP = addr.host
                    case .v6(let addr): resolvedIP = addr.host
                    default: resolvedIP = nil
                    }
                    if let ip = resolvedIP, self.filter.isBlockedCIDR(ip) {
                        proxyLog.warning("DENY (resolved CIDR) CONNECT \(host):\(port) -> \(ip)")
                        remoteChannel.close(promise: nil)
                        self.sendResponse(context: context, status: .forbidden,
                            body: "Blocked: resolved to private IP \(ip)\n")
                        return
                    }
                    self.tunnelEstablished(context: context, remoteChannel: remoteChannel)
                case .failure(let error):
                    proxyLog.error("Failed to connect to \(host):\(port): \(error)")
                    self.sendResponse(context: context, status: .badGateway, body: "Cannot connect to \(host):\(port)\n")
                }
            }
    }

    /// Tunnel is established — send 200, then switch to raw byte relay.
    private func tunnelEstablished(context: ChannelHandlerContext, remoteChannel: Channel) {
        // Send 200 Connection Established.
        let head = HTTPResponseHead(version: .http1_1, status: .ok)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)

        // Remove HTTP handlers — switch to raw bytes.
        let clientChannel = context.channel
        context.pipeline.removeHandler(self, promise: nil)

        // Remove HTTP codec handlers too.
        clientChannel.pipeline.handler(type: HTTPResponseEncoder.self).whenSuccess { encoder in
            clientChannel.pipeline.removeHandler(encoder, promise: nil)
        }
        clientChannel.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self).whenSuccess { decoder in
            clientChannel.pipeline.removeHandler(decoder, promise: nil)
        }

        // Set up bidirectional relay.
        let relay1 = ByteRelayHandler(partner: remoteChannel)
        let relay2 = ByteRelayHandler(partner: clientChannel)

        clientChannel.pipeline.addHandler(relay1).whenComplete { _ in
            remoteChannel.pipeline.addHandler(relay2).whenComplete { _ in
                // Start reading.
                clientChannel.read()
                remoteChannel.read()
            }
        }
    }

    private func sendResponse(context: ChannelHandlerContext, status: HTTPResponseStatus, body: String) {
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
}

// MARK: - Byte Relay Handler

/// Relays raw bytes between two channels (bidirectional tunnel).
private final class ByteRelayHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    let partner: Channel

    init(partner: Channel) {
        self.partner = partner
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)
        partner.writeAndFlush(buffer, promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        partner.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
