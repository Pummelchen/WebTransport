import Foundation
import Testing
@testable import WebTransportNetworkRuntime

/// F-swift-perf-tests-08: the bounded-read contract of the shipped stream API.
///
/// `WebTransportNetworkBidirectionalStream.receive(maximumBytes:)` documents
/// that it returns at most `maximumBytes`. A stream accepted from the wire keeps
/// the prefix-stripped remainder of its first chunk as a buffered initial payload,
/// and that path used to return the whole buffer regardless of the bound
/// (F-swift-architecture-04, fixed in commit 02745a9). The end-to-end success
/// path is covered by `WebTransportStreamReceiveBoundTests`; this test drives the
/// runtime API directly and pins the boundary cases the success path does not:
/// a zero and a negative bound read nothing and keep the buffer, a positive bound
/// is honoured exactly, and the unread remainder is delivered by the reads that
/// follow.
@Test
func runtimeReceiveHonoursMaximumBytesAndKeepsTheUnreadRemainder() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
    defer { server.shutdown() }

    let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
    let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
    async let connecting = client.connectSession(to: target, timeoutMilliseconds: 15_000)
    let serverSession = try await server.acceptSession(timeoutMilliseconds: 15_000)
    let clientSession = try await connecting

    // One write carries the stream prefix together with the payload, and the
    // sender waits before the peer accepts, so the accepted stream holds a
    // buffered initial payload far larger than every bound used below.
    let payload = Data((0..<65_536).map { UInt8($0 % 251) })
    let outbound = try await clientSession.openBidirectionalStream(timeoutMilliseconds: 15_000)
    try await outbound.send(payload, endOfStream: true, timeoutMilliseconds: 15_000)
    try await Task.sleep(for: .milliseconds(300))

    let inbound = try await serverSession.acceptBidirectionalStream(timeoutMilliseconds: 15_000)

    // Boundary: a zero-length read returns nothing and must leave the buffer
    // intact for the next read.
    let zero = try await inbound.receive(maximumBytes: 0, timeoutMilliseconds: 15_000)
    #expect(zero.isEmpty, "receive(maximumBytes: 0) returned \(zero.count) bytes")

    // A negative bound is the same request as zero, not an unbounded read.
    let negative = try await inbound.receive(maximumBytes: -1, timeoutMilliseconds: 15_000)
    #expect(negative.isEmpty, "receive(maximumBytes: -1) returned \(negative.count) bytes")

    // The bound is honoured on the buffered path: before the fix this returned
    // the whole ~64 KiB payload.
    let first = try await inbound.receive(maximumBytes: 1, timeoutMilliseconds: 15_000)
    #expect(first.count == 1, "receive(maximumBytes: 1) returned \(first.count) bytes")
    #expect(first == Data(payload.prefix(1)), "the first byte is out of order")

    var received = zero
    received.append(negative)
    received.append(first)
    while received.count < payload.count {
        let chunk = try await inbound.receive(maximumBytes: 4_096, timeoutMilliseconds: 15_000)
        if chunk.isEmpty {
            break
        }
        received.append(chunk)
    }
    #expect(
        received == payload,
        "the unread remainder was not preserved: \(received.count) of \(payload.count) bytes")
}
