import Foundation
@preconcurrency import NIOCore
import NIOPosix
import Testing

@testable import sandbox

@Suite(.serialized) struct ProxyServerTests {
    // MARK: - CONNECT (HTTPS tunneling)

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

    @Test func cidrBlocksPrivateIP() async throws {
        // Allow mode passes the domain filter, but 127.0.0.1 is in default blocked CIDRs.
        // The CIDR check fires pre-connect for IP literals, so no listener is needed.
        let response = try await proxyConnect(
            policy: .allow,
            target: "127.0.0.1:9999"
        )
        #expect(response.contains("HTTP/1.1 403"))
        #expect(response.contains("blocked CIDR"))
    }

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

    /// A client may pipeline tunneled bytes in the same write as the CONNECT
    /// header (e.g. a TLS ClientHello appended after the \r\n\r\n). The proxy
    /// must forward those overflow bytes to the remote, not drop them.
    @Test func tunnelForwardsPipelinedBytes() async throws {
        let echo = try await EchoServer.start()
        defer { echo.shutdown() }

        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )

        let socketPath = "/tmp/tp-\(UUID().uuidString).sock"
        let server = ProxyServer(socketPath: socketPath, filter: DomainFilter(policy: policy))
        let serverTask = Task { try await server.run() }
        defer {
            serverTask.cancel()
            unlink(socketPath)
        }
        try await waitForSocket(socketPath)

        let target = "127.0.0.1:\(echo.port)"
        let payload = "PIPELINED-PAYLOAD"
        let pipelinedRequest = "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\r\n\(payload)"

        let echoed = try await Task.detached {
            let fd = try connectToUDS(socketPath)
            defer { close(fd) }
            setReadTimeout(fd, seconds: 3)

            // Send CONNECT + payload in one write so the overflow lands in the
            // header parser's buffer.
            _ = pipelinedRequest.withCString { Darwin.write(fd, $0, pipelinedRequest.utf8.count) }

            // Drain the 200 response, then read whatever echo sends back.
            var buf = [UInt8](repeating: 0, count: 4096)
            var combined = ""
            while combined.count < 256 {
                let n = Darwin.read(fd, &buf, buf.count)
                if n <= 0 { break }
                combined += String(bytes: buf[..<n], encoding: .utf8) ?? ""
                if combined.contains(payload) { break }
            }
            return combined
        }.value

        #expect(echoed.contains("200"))
        #expect(
            echoed.contains(payload),
            "Proxy dropped bytes pipelined after the CONNECT header. Got: \(echoed)")
    }

    // MARK: - Plain HTTP forward proxy

    @Test func plainHTTPForwardedToTarget() async throws {
        let echo = try await EchoServer.start(closeAfterEcho: true)
        defer { echo.shutdown() }

        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )

        let start = ContinuousClock.now
        let response = try await proxySend(
            policy: policy,
            request:
                "GET http://127.0.0.1:\(echo.port)/test HTTP/1.1\r\nHost: 127.0.0.1:\(echo.port)\r\n\r\n"
        )
        let elapsed = ContinuousClock.now - start
        // The echo server echoes back the re-encoded request. Verify forwarding, not 403.
        #expect(!response.contains("HTTP/1.1 403"))
        #expect(response.contains("GET /test HTTP/1.1"))
        // The relay must close the client connection when the remote closes.
        // Without proper teardown, this test blocks for the 3-second read timeout.
        #expect(elapsed < .seconds(2), "Relay teardown too slow — connection not closing on remote close")
    }

    @Test func plainHTTPPostWithBody() async throws {
        let echo = try await EchoServer.start(closeAfterEcho: true)
        defer { echo.shutdown() }

        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )

        let body = "key=value&foo=bar"
        let start = ContinuousClock.now
        let response = try await proxySend(
            policy: policy,
            request:
                "POST http://127.0.0.1:\(echo.port)/submit HTTP/1.1\r\nHost: 127.0.0.1:\(echo.port)\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
        )
        let elapsed = ContinuousClock.now - start
        #expect(!response.contains("HTTP/1.1 403"))
        #expect(response.contains("POST /submit HTTP/1.1"))
        #expect(response.contains("Content-Length: \(body.utf8.count)"))
        #expect(response.contains(body))
        #expect(elapsed < .seconds(2), "Relay teardown too slow — connection not closing on remote close")
    }

    @Test func plainHTTPBlockedHostReturns403() async throws {
        let response = try await proxySend(
            policy: .deny(allowedHosts: ["good.example.com"]),
            request: "GET http://evil.com/path HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        )
        #expect(response.contains("HTTP/1.1 403"))
        #expect(response.contains("Blocked"))
    }

    @Test func plainHTTPCIDRBlocksPrivateIP() async throws {
        // CIDR check is pre-connect for IP literals, so no listener is needed.
        let response = try await proxySend(
            policy: .allow,
            request:
                "GET http://127.0.0.1:9999/ HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n"
        )
        #expect(response.contains("HTTP/1.1 403"))
        #expect(response.contains("blocked CIDR"))
    }

    @Test func plainHTTPHostHeaderFallback() async throws {
        // Non-absolute URI with Host header — should still work.
        let response = try await proxySend(
            policy: .deny(allowedHosts: ["good.example.com"]),
            request: "GET /path HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        )
        #expect(response.contains("HTTP/1.1 403"))
        #expect(response.contains("Blocked"))
    }

    // MARK: - Adversarial: smuggling primitives at the origin
    //
    // These tests use a CaptureServer that records the exact bytes the proxy
    // writes to "origin" so we can assert what an upstream parser would see.

    @Test func transferEncodingNotForwardedToOrigin() async throws {
        // hopByHopHeaders includes transfer-encoding (RFC 7230 §6.1) so the
        // proxy can't be paired with a smaller Content-Length to produce the
        // classic TE/CL request-smuggling primitive at the origin.
        let capture = try await CaptureServer.start()
        defer { capture.shutdown() }

        // No CIDR blocks so 127.0.0.1 isn't rejected pre-connect.
        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [], blockedHosts: [], blockedCIDRs: [])

        let body = "0\r\n\r\n"
        let smuggled =
            "GET http://127.0.0.1:\(capture.port)/ HTTP/1.1\r\n"
            + "Host: 127.0.0.1:\(capture.port)\r\n"
            + "Content-Length: \(body.utf8.count)\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "\r\n"
            + body

        // CaptureServer never responds, so proxySend's read will time out.
        // We only care about what reached CaptureServer, so swallow the
        // client-side failure.
        _ = try? await proxySend(policy: policy, request: smuggled)

        let bytes = try await capture.waitForBytes(atLeast: 1, timeout: .seconds(2))
        let received = String(bytes: bytes, encoding: .utf8) ?? ""
        let headerEnd = received.range(of: "\r\n\r\n")?.lowerBound ?? received.endIndex
        let headerBlock = received[..<headerEnd].lowercased()
        #expect(
            !(headerBlock.contains("content-length:") && headerBlock.contains("transfer-encoding:")),
            "Both CL and TE survived the proxy — TE/CL smuggling primitive at origin")
    }

    @Test func bareLFInHeaderNameNotForwardedToOrigin() async throws {
        // parseRequestBytes splits on "\r\n", so a header *name* containing a
        // bare LF (e.g. "X-Pwn\nHost") used to survive parsing and re-emit
        // verbatim — origins tolerant of bare LF would smuggle a Host header.
        // The parser now rejects names with control chars (malformed request).
        let capture = try await CaptureServer.start()
        defer { capture.shutdown() }

        let policy = NetworkPolicy(
            direction: .allow, allowedHosts: [], blockedHosts: [], blockedCIDRs: [])

        let request =
            "GET http://127.0.0.1:\(capture.port)/ HTTP/1.1\r\n"
            + "Host: 127.0.0.1:\(capture.port)\r\n"
            + "X-Pwn\nHost: smuggled.example.com: real-value\r\n"
            + "\r\n"

        // The proxy now rejects the malformed request and closes the
        // connection without responding, so proxySend's read fails. We only
        // care about what (if anything) reached origin.
        _ = try? await proxySend(policy: policy, request: request)

        // Either the proxy rejected the request (no bytes at origin) or it
        // forwarded scrubbed bytes — either way the bare-LF pattern must
        // not appear verbatim in what the origin saw. The proxy rejects this
        // request before connecting to origin, so the success path is "no
        // bytes received"; a short timeout keeps CI fast since we expect the
        // wait to fall through.
        let bytes = (try? await capture.waitForBytes(atLeast: 1, timeout: .milliseconds(100))) ?? []
        let received = String(bytes: bytes, encoding: .utf8) ?? ""
        #expect(!received.contains("X-Pwn\nHost: smuggled.example.com"))
    }

    // MARK: - Adversarial: parseAbsoluteURI edge cases

    @Test func plainHTTPWithUserinfoMisparsesAuthority() async throws {
        // parseAbsoluteURI doesn't handle the userinfo@ delimiter (RFC 3986 §3.2).
        // A URL like http://user:pass@host/path has authority "user:pass@host".
        // parseHostPort sees two colons → treats it as bare IPv6 → host becomes
        // the entire "user:pass@host" string → DNS fails → 502.
        // The proxy should either strip userinfo and connect to "host", or reject
        // the request as malformed.
        let echo = try await EchoServer.start(closeAfterEcho: true)
        defer { echo.shutdown() }

        let response = try await proxySend(
            policy: NetworkPolicy(direction: .allow, allowedHosts: [], blockedHosts: [], blockedCIDRs: []),
            request: "GET http://user:pass@127.0.0.1:\(echo.port)/path HTTP/1.1\r\nHost: 127.0.0.1:\(echo.port)\r\n\r\n"
        )
        // Correct behavior: strip userinfo, forward to 127.0.0.1:port, get echo back.
        // Actual behavior: misparses host, gets 502 (DNS failure) or connects to wrong host.
        #expect(
            response.contains("GET /path HTTP/1.1"),
            "Proxy should strip userinfo and forward to the real host. Got: \(response.prefix(200))")
    }

    @Test func plainHTTPUserinfoDoesNotBypassBlocklist() async throws {
        // An attacker could try http://innocent@blocked.com/path to bypass the
        // domain filter, since parseAbsoluteURI misparses the authority.
        let response = try await proxySend(
            policy: .deny(allowedHosts: ["good.example.com"]),
            request: "GET http://good.example.com@evil.com/path HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        )
        // The request should be blocked because the actual host is evil.com.
        // With the userinfo bug, the parsed host is "good.example.com@evil.com"
        // which doesn't match the allowlist → denied. So the bug accidentally
        // fails safe here. But the error reason will reference the wrong host.
        #expect(
            response.contains("HTTP/1.1 403") || response.contains("HTTP/1.1 502"),
            "Request with userinfo to blocked host should not succeed")
    }

    // MARK: - SOCKS5

    @Test func socks5BlockedHostDenied() async throws {
        let response = try await socks5Send(
            policy: .deny(allowedHosts: ["good.example.com"]),
            host: .domain("evil.com"),
            port: 443
        )
        // Greeting reply [0x05, 0x00] + error reply [0x05, 0x02, ...]
        #expect(response.count >= 4)
        #expect(response[0] == 0x05)  // greeting version
        #expect(response[1] == 0x00)  // no auth
        #expect(response[2] == 0x05)  // request version
        #expect(response[3] == 0x02)  // connection not allowed
    }

    @Test func socks5AllowedHostConnects() async throws {
        let echo = try await EchoServer.start()
        defer { echo.shutdown() }

        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )

        let echoed = try await socks5ConnectAndRelay(
            policy: policy,
            host: .ipv4(127, 0, 0, 1),
            port: echo.port,
            payload: "hello socks5"
        )
        #expect(echoed == "hello socks5")
    }

    @Test func socks5DomainConnect() async throws {
        let echo = try await EchoServer.start()
        defer { echo.shutdown() }

        let policy = NetworkPolicy(
            direction: .allow,
            allowedHosts: [],
            blockedHosts: [],
            blockedCIDRs: []
        )

        let echoed = try await socks5ConnectAndRelay(
            policy: policy,
            host: .domain("127.0.0.1"),
            port: echo.port,
            payload: "hello domain"
        )
        #expect(echoed == "hello domain")
    }

    @Test func socks5UnsupportedCommandRejected() async throws {
        // BIND command (0x02) should be rejected.
        let response = try await socks5Send(
            policy: .allow,
            host: .ipv4(127, 0, 0, 1),
            port: 80,
            command: 0x02  // BIND
        )
        #expect(response.count >= 4)
        #expect(response[3] == 0x07)  // command not supported
    }

    @Test func socks5CIDRBlocksPrivateIP() async throws {
        let echo = try await EchoServer.start()
        defer { echo.shutdown() }

        // Allow-mode passes domain filter, but default CIDRs block 127.0.0.1.
        let response = try await socks5Send(
            policy: .allow,
            host: .ipv4(127, 0, 0, 1),
            port: echo.port
        )
        #expect(response.count >= 4)
        #expect(response[3] == 0x02)  // connection not allowed (CIDR)
    }

    @Test func socks5IPv6AddressType() async throws {
        // IPv6 loopback (::1) not in allowed list — verifies atyp 0x04 parsing.
        let loopback: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let response = try await socks5Send(
            policy: .deny(allowedHosts: ["good.example.com"]),
            host: .ipv6(loopback),
            port: 443
        )
        #expect(response.count >= 4)
        #expect(response[0] == 0x05)  // greeting version
        #expect(response[1] == 0x00)  // no auth
        #expect(response[2] == 0x05)  // request version
        #expect(response[3] == 0x02)  // connection not allowed
    }

    @Test func socks5InvalidVersionRejected() async throws {
        // Send SOCKS4 version — should be rejected.
        let socketPath = "/tmp/tp-\(UUID().uuidString).sock"
        let server = ProxyServer(socketPath: socketPath, filter: DomainFilter(policy: .allow))
        let serverTask = Task { try await server.run() }
        defer {
            serverTask.cancel()
            unlink(socketPath)
        }
        try await waitForSocket(socketPath)

        let response = try await Task.detached {
            let fd = try connectToUDS(socketPath)
            defer { close(fd) }
            setReadTimeout(fd, seconds: 3)

            // SOCKS4 greeting: version 4 (starts with 0x04, but detection routes 0x04 to HTTP)
            // Send 0x05 version with 0x04 in the SOCKS5 version field of the request
            var data: [UInt8] = [0x05, 0x01, 0x00]  // valid greeting
            data += [0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]  // bad version in request
            data.withUnsafeBufferPointer { ptr in
                guard let base = ptr.baseAddress else { return }
                _ = Darwin.write(fd, base, data.count)
            }
            return try readAllBytes(fd)
        }.value

        // Greeting reply + error reply (version mismatch in request)
        #expect(response.count >= 4)
        #expect(response[2] == 0x05)
        #expect(response[3] == 0x01)  // general failure
    }

    // MARK: - HTTP Helpers

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

    // MARK: - SOCKS5 Helpers

    enum Socks5Host {
        case ipv4(UInt8, UInt8, UInt8, UInt8)
        case ipv6([UInt8])  // 16 bytes
        case domain(String)
    }

    /// Build a SOCKS5 greeting + request, send it, and return all response bytes.
    private func socks5Send(
        policy: NetworkPolicy,
        host: Socks5Host,
        port: Int,
        command: UInt8 = 0x01
    ) async throws -> [UInt8] {
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

            // Greeting: version 5, 1 method (no auth)
            var data: [UInt8] = [0x05, 0x01, 0x00]
            // Request header: version 5, command, reserved
            data += [0x05, command, 0x00]
            // Address
            switch host {
            case .ipv4(let a, let b, let c, let d):
                data += [0x01, a, b, c, d]
            case .ipv6(let bytes):
                precondition(bytes.count == 16)
                data += [0x04] + bytes
            case .domain(let name):
                data += [0x03, UInt8(name.utf8.count)]
                data += Array(name.utf8)
            }
            // Port (big-endian)
            data += [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)]

            data.withUnsafeBufferPointer { ptr in
                guard let base = ptr.baseAddress else { return }
                _ = Darwin.write(fd, base, data.count)
            }
            return try readAllBytes(fd)
        }.value
    }

    /// SOCKS5 connect + relay: perform handshake, then send payload and read echoed response.
    private func socks5ConnectAndRelay(
        policy: NetworkPolicy,
        host: Socks5Host,
        port: Int,
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

            var tv = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            // Send greeting
            let greeting: [UInt8] = [0x05, 0x01, 0x00]
            greeting.withUnsafeBufferPointer { ptr in
                guard let base = ptr.baseAddress else { return }
                _ = Darwin.write(fd, base, greeting.count)
            }

            // Read greeting reply (2 bytes: [0x05, 0x00])
            var greetReply = [UInt8](repeating: 0, count: 2)
            let greetN = Darwin.read(fd, &greetReply, 2)
            guard greetN == 2, greetReply[0] == 0x05, greetReply[1] == 0x00 else {
                throw ProxyTestError.unexpectedResponse("bad socks5 greeting: \(greetReply)")
            }

            // Build connect request
            var request: [UInt8] = [0x05, 0x01, 0x00]
            switch host {
            case .ipv4(let a, let b, let c, let d):
                request += [0x01, a, b, c, d]
            case .ipv6(let bytes):
                precondition(bytes.count == 16)
                request += [0x04] + bytes
            case .domain(let name):
                request += [0x03, UInt8(name.utf8.count)]
                request += Array(name.utf8)
            }
            request += [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)]

            request.withUnsafeBufferPointer { ptr in
                guard let base = ptr.baseAddress else { return }
                _ = Darwin.write(fd, base, request.count)
            }

            // Read connect reply (10 bytes for IPv4 response)
            var connectReply = [UInt8](repeating: 0, count: 10)
            let connN = Darwin.read(fd, &connectReply, 10)
            guard connN == 10, connectReply[1] == 0x00 else {
                throw ProxyTestError.unexpectedResponse(
                    "socks5 connect failed: reply=\(connectReply[0 ..< min(connN, 10)])"
                )
            }

            // Send payload through tunnel
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

    // MARK: - Common Helpers

    private func waitForSocket(_ path: String) async throws {
        for _ in 0..<100 {
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

private func readAllBytes(_ fd: Int32) throws -> [UInt8] {
    var response = [UInt8]()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = Darwin.read(fd, &buffer, buffer.count)
        if n <= 0 { break }
        response.append(contentsOf: buffer[..<n])
    }
    guard !response.isEmpty else { throw ProxyTestError.readFailed }
    return response
}

// MARK: - Echo server

/// Minimal TCP echo server for testing the proxy byte relay.
private struct EchoServer {
    let port: Int
    private let channel: Channel
    private let group: MultiThreadedEventLoopGroup

    static func start(closeAfterEcho: Bool = false) async throws -> EchoServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(EchoHandler(closeAfterEcho: closeAfterEcho))
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

    let closeAfterEcho: Bool

    init(closeAfterEcho: Bool = false) {
        self.closeAfterEcho = closeAfterEcho
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if closeAfterEcho {
            let channel = context.channel
            context.writeAndFlush(data).whenComplete { _ in
                channel.close(promise: nil)
            }
        } else {
            context.writeAndFlush(data, promise: nil)
        }
    }
}

// MARK: - Capture server
//
// Like EchoServer but records every byte received without echoing. Used by
// the smuggling-primitive tests that need to inspect what the proxy actually
// wrote to the origin.

private final class CaptureServer: @unchecked Sendable {
    let port: Int
    private let channel: Channel
    private let group: MultiThreadedEventLoopGroup
    private let recorder: ByteRecorder

    private init(
        port: Int, channel: Channel, group: MultiThreadedEventLoopGroup, recorder: ByteRecorder
    ) {
        self.port = port
        self.channel = channel
        self.group = group
        self.recorder = recorder
    }

    static func start() async throws -> CaptureServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let recorder = ByteRecorder()
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(CaptureHandler(recorder: recorder))
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        guard let port = channel.localAddress?.port else {
            throw ProxyTestError.bindFailed
        }
        return CaptureServer(port: port, channel: channel, group: group, recorder: recorder)
    }

    func waitForBytes(atLeast: Int, timeout: Duration) async throws -> [UInt8] {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            let snapshot = recorder.snapshot()
            if snapshot.count >= atLeast { return snapshot }
            try await Task.sleep(for: .milliseconds(20))
        }
        let snapshot = recorder.snapshot()
        if snapshot.isEmpty { throw ProxyTestError.readFailed }
        return snapshot
    }

    func shutdown() {
        channel.close(promise: nil)
        try? group.syncShutdownGracefully()
    }
}

private final class ByteRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: [UInt8] = []

    func append(_ chunk: [UInt8]) {
        lock.lock()
        defer { lock.unlock() }
        bytes.append(contentsOf: chunk)
    }

    func snapshot() -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return bytes
    }
}

private final class CaptureHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    let recorder: ByteRecorder

    init(recorder: ByteRecorder) {
        self.recorder = recorder
    }

    func channelRead(context _: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        if let bytes = buf.readBytes(length: buf.readableBytes) {
            recorder.append(bytes)
        }
        // Don't echo, don't close — just record. The proxy will time out
        // waiting for a response, which is fine since we only care about
        // what was sent.
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
