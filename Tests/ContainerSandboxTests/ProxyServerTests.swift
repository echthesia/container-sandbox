import Foundation
@preconcurrency import NIOCore
import NIOPosix
@testable import sandbox
import Testing

struct ProxyServerTests {
    // MARK: - Domain filtering

    @Test func blockedHostReturns403() async throws {
        let response = try await proxyConnect(
            policy: .deny(allowedHosts: ["good.example.com"]),
            target: "evil.com:443"
        )
        #expect(response.contains("HTTP/1.1 403"))
        #expect(response.contains("Blocked"))
    }

    @Test func allowedHostAttemptsConnection() async throws {
        // Use a policy with no CIDR blocks so 127.0.0.1 isn't rejected post-connect.
        // Port 1 is almost certainly not listening, so connect fails → 502 Bad Gateway.
        // The key assertion: it's NOT 403 (the domain filter allowed it).
        let policy = NetworkPolicy(
            direction: .deny,
            allowedHosts: ["127.0.0.1"],
            blockedHosts: [],
            blockedCIDRs: []
        )
        let response = try await proxyConnect(policy: policy, target: "127.0.0.1:1")
        #expect(response.contains("HTTP/1.1 502"))
    }

    @Test func plainHTTPRejected() async throws {
        let response = try await proxySend(
            policy: .allow,
            request: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        #expect(response.contains("HTTP/1.1 403"))
        #expect(response.contains("Plain HTTP not supported"))
    }

    // MARK: - CIDR blocking (post-connect)

    @Test func cidrBlocksPrivateIP() async throws {
        // Allow mode passes the domain filter, but 127.0.0.1 is in default blocked CIDRs.
        // Start a real local server so the TCP connect succeeds — the CIDR check fires post-connect.
        let echo = try await EchoServer.start()
        defer { echo.shutdown() }

        let response = try await proxyConnect(
            policy: .allow,
            target: "127.0.0.1:\(echo.port)"
        )
        #expect(response.contains("HTTP/1.1 403"))
        #expect(response.contains("private IP"))
    }

    // MARK: - Byte relay

    @Test func tunnelRelaysData() async throws {
        let echo = try await EchoServer.start()
        defer { echo.shutdown() }

        // No CIDR blocks so we can actually connect to 127.0.0.1.
        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )

        let echoed = try await proxyConnectAndRelay(
            policy: policy,
            target: "127.0.0.1:\(echo.port)",
            payload: "hello from proxy test"
        )
        #expect(echoed == "hello from proxy test")
    }

    // MARK: - Helpers

    /// Send a CONNECT request through a fresh proxy and return the raw response.
    private func proxyConnect(policy: NetworkPolicy, target: String) async throws -> String {
        try await proxySend(
            policy: policy,
            request: "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\r\n"
        )
    }

    /// Send an arbitrary HTTP request through a fresh proxy and return the raw response.
    private func proxySend(policy: NetworkPolicy, request: String) async throws -> String {
        let socketPath = "/tmp/tp-\(UUID().uuidString).sock"
        let server = ProxyServer(socketPath: socketPath, filter: DomainFilter(policy: policy))
        let serverTask = Task { try await server.run() }
        defer {
            serverTask.cancel()
            unlink(socketPath)
        }

        try await waitForSocket(socketPath)

        return try await Task.detached {
            let fd = try connectToUDS(socketPath)
            defer { close(fd) }

            setReadTimeout(fd, seconds: 3)

            _ = request.withCString { Darwin.write(fd, $0, request.utf8.count) }

            return try readAll(fd)
        }.value
    }

    /// CONNECT through a proxy, then send payload bytes and read the echoed response.
    private func proxyConnectAndRelay(
        policy: NetworkPolicy,
        target: String,
        payload: String
    ) async throws -> String {
        let socketPath = "/tmp/tp-\(UUID().uuidString).sock"
        let server = ProxyServer(socketPath: socketPath, filter: DomainFilter(policy: policy))
        let serverTask = Task { try await server.run() }
        defer {
            serverTask.cancel()
            unlink(socketPath)
        }

        try await waitForSocket(socketPath)

        return try await Task.detached {
            let fd = try connectToUDS(socketPath)
            defer { close(fd) }

            // Send CONNECT
            let connectReq = "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\r\n"
            _ = connectReq.withCString { Darwin.write(fd, $0, connectReq.utf8.count) }

            // Drain the full HTTP response (headers + any chunked framing from the encoder).
            // Use a short timeout so we catch trailing bytes without blocking long.
            var tv = timeval(tv_sec: 0, tv_usec: 200_000)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            var httpBuf = [UInt8](repeating: 0, count: 4096)
            var httpResponse = ""
            while true {
                let n = Darwin.read(fd, &httpBuf, httpBuf.count)
                if n <= 0 { break }
                httpResponse += String(bytes: httpBuf[..<n], encoding: .utf8) ?? ""
            }
            guard httpResponse.contains("200") else {
                throw ProxyTestError.unexpectedResponse(httpResponse)
            }

            // Send payload through the tunnel (relay handlers are now active)
            _ = payload.withCString { Darwin.write(fd, $0, payload.utf8.count) }

            // Read echoed data
            tv = timeval(tv_sec: 1, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            var buffer = [UInt8](repeating: 0, count: 4096)
            let n = Darwin.read(fd, &buffer, buffer.count)
            guard n > 0 else { throw ProxyTestError.readFailed }

            return String(bytes: buffer[..<n], encoding: .utf8) ?? ""
        }.value
    }

    private func waitForSocket(_ path: String) async throws {
        for _ in 0 ..< 100 {
            if FileManager.default.fileExists(atPath: path) { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw ProxyTestError.socketTimeout
    }
}

// MARK: - POSIX socket helpers

private func connectToUDS(_ path: String) throws -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw ProxyTestError.socketFailed }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    // Compute size before the mutable borrow to avoid exclusivity violation.
    let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
    let copyLen = min(path.utf8.count + 1, maxLen)
    path.withCString { cstr in
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            _ = memcpy(ptr, cstr, copyLen)
        }
    }

    let result = withUnsafePointer(to: addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
            Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard result == 0 else {
        close(fd)
        throw ProxyTestError.connectFailed
    }

    return fd
}

private func setReadTimeout(_ fd: Int32, seconds: Int) {
    var tv = timeval(tv_sec: seconds, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
}

private func readAll(_ fd: Int32) throws -> String {
    var response = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = Darwin.read(fd, &buffer, buffer.count)
        if n <= 0 { break }
        response.append(contentsOf: buffer[..<n])
    }
    guard !response.isEmpty else { throw ProxyTestError.readFailed }
    return String(data: response, encoding: .utf8) ?? ""
}

// MARK: - Echo server

/// Minimal TCP echo server for testing the proxy byte relay.
private struct EchoServer {
    let port: Int
    private let channel: Channel
    private let group: MultiThreadedEventLoopGroup

    static func start() async throws -> EchoServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(EchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        guard let port = channel.localAddress?.port else {
            throw ProxyTestError.bindFailed
        }
        return EchoServer(port: port, channel: channel, group: group)
    }

    func shutdown() {
        channel.close(promise: nil)
        try? group.syncShutdownGracefully()
    }
}

private final class EchoHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }
}

// MARK: - Errors

private enum ProxyTestError: Error {
    case socketFailed
    case connectFailed
    case readFailed
    case socketTimeout
    case unexpectedResponse(String)
    case bindFailed
}
