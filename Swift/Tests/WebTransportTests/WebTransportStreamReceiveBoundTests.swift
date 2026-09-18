import Foundation
import Testing
import WebTransport
import WebTransportHTTP3Core
import WebTransportNetworkRuntime
import WebTransportQUICCore

/// F-swift-architecture-04: a stream accepted from the wire carries the
/// prefix-stripped remainder of its first chunk as a buffered initial payload.
/// `WebTransportBidirectionalStream.receive(maximumBytes:)` returned that whole
/// payload before consulting `maximumBytes`, so `receive(maximumBytes: 1)` could
/// return tens of kilobytes. The bound has to hold on that path too, with the
/// unread remainder kept for the next read.
@Test
func receiveHonoursMaximumBytesWhenTheStreamHasABufferedInitialPayload() async throws {
    try await WebTransportProcessSupport.withExclusiveProcessExecution {
        try await runInitialPayloadReceiveBound()
    }
}

private func runInitialPayloadReceiveBound() async throws {
    let payload = Data(repeating: 0x5a, count: 65_536)
    var lastError: Error?
    for _ in 0..<5 {
        do {
            let server = WebTransportServer(
                configuration: WebTransportServerConfiguration(
                    authority: "localhost",
                    path: "/wt",
                    origin: "https://localhost",
                    supportedProtocols: ["demo.v1"],
                    timeoutMilliseconds: 30_000
                )
            )
            let client = WebTransportClient(
                configuration: WebTransportClientConfiguration(
                    authority: "localhost",
                    path: "/wt",
                    origin: "https://localhost",
                    availableProtocols: ["demo.v1"],
                    trustPolicy: .localDevelopmentSelfSigned,
                    timeoutMilliseconds: 30_000
                )
            )
            let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
            defer { listener.shutdown() }

            async let accepted = listener.acceptSession()
            let clientSession = try await client.connect(to: listener.localEndpoint)
            let serverSession = try await accepted

            // One send carries the stream prefix and the whole payload, so the
            // server's first `atMost: 64 KiB` read sees a buffered initial payload
            // far larger than the one byte the reader is about to ask for.
            let outbound = try await clientSession.openBidirectionalStream()
            try await outbound.send(payload, endOfStream: true)
            // Let the bytes reach the server's QUIC receive buffer before it
            // takes the first chunk; otherwise the first read can see only the
            // prefix and the bound would not be exercised.
            try await Task.sleep(for: .milliseconds(300))

            let inbound = try await serverSession.acceptBidirectionalStream()
            let first = try await inbound.receive(maximumBytes: 1)
            #expect(first.count == 1, "receive(maximumBytes: 1) returned \(first.count) bytes")

            let received = try await drain(inbound, startingWith: first, expected: payload.count)
            #expect(received == payload)

            try await clientSession.close()
            try await Task.sleep(for: .seconds(2))
            return
        } catch {
            lastError = error
            try await Task.sleep(for: .seconds(2))
        }
    }
    throw lastError ?? QUICCodecError.malformed("initial-payload receive bound exchange failed")
}

/// Reads until the accumulated bytes reach `expected`, or the peer stops sending.
private func drain(
    _ inbound: WebTransportBidirectionalStream,
    startingWith first: Data,
    expected: Int
) async throws -> Data {
    var received = first
    while received.count < expected {
        let chunk = try await inbound.receive(maximumBytes: 64 * 1024)
        if chunk.isEmpty {
            break
        }
        received.append(chunk)
    }
    return received
}
