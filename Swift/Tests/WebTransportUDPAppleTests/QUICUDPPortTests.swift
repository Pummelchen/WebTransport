import Darwin
import Foundation
import Testing
import WebTransportQUICCore
@testable import WebTransportUDPApple

@Test
func udpPortExchangesNativeFramesOnLoopback() throws {
    let server = try QUICUDPPort()
    let client = try QUICUDPPort()

    let frames: [QUICFrame] = [
        .stream(id: 0, offset: 0, fin: false, data: Data("hello".utf8)),
        .datagram(Data("dgram".utf8)),
    ]
    try client.send(try QUICFrame.encodeFrames(frames), to: server.localEndpoint)

    let (bytes, endpoint) = try server.receive(timeoutMilliseconds: 1_000)
    #expect(endpoint.port == client.localEndpoint.port)
    #expect(try QUICFrame.decodeFrames(bytes) == frames)
}

@Test
func udpPortExchangesNativeFramesOnIPv6Loopback() throws {
    let server = try QUICUDPPort(bindHost: "::1")
    let client = try QUICUDPPort(bindHost: "::1")

    let frames: [QUICFrame] = [
        .stream(id: 4, offset: 0, fin: true, data: Data("hello-v6".utf8)),
        .datagram(Data("dgram-v6".utf8)),
    ]
    try client.send(try QUICFrame.encodeFrames(frames), to: server.localEndpoint)

    let (bytes, endpoint) = try server.receive(timeoutMilliseconds: 1_000)
    #expect(endpoint.host == "::1")
    #expect(endpoint.port == client.localEndpoint.port)
    #expect(try QUICFrame.decodeFrames(bytes) == frames)
}

@Test
func udpPortRejectsNonLoopbackAddress() throws {
    #expect(throws: Error.self) {
        _ = try QUICUDPPort(bindHost: "0.0.0.0")
    }
    let port = try QUICUDPPort()
    #expect(throws: Error.self) {
        try port.send(Data("blocked".utf8), to: QUICUDPEndpoint(host: "192.0.2.1", port: 4433))
    }
}

@Test
func udpPortRejectsInvalidReceiveConfiguration() throws {
    let server = try QUICUDPPort()

    #expect(throws: Error.self) {
        _ = try server.receive(maximumBytes: 0, timeoutMilliseconds: 1)
    }
    #expect(throws: Error.self) {
        _ = try server.receive(maximumBytes: -1, timeoutMilliseconds: 1)
    }
    #expect(throws: Error.self) {
        _ = try server.receive(maximumBytes: 65_536, timeoutMilliseconds: 1)
    }
    #expect(throws: Error.self) {
        _ = try server.receive(maximumBytes: 1, timeoutMilliseconds: -1)
    }
}

/// F-swift-perf-tests-09: the cancellation observation must depend on the port.
///
/// The old body caught and discarded every `receive` error and asserted only
/// `Task.isCancelled`, which `task.cancel()` sets whatever the port does. It
/// therefore passed with a receive stubbed to return immediately (no timeout was
/// ever observed) and could not detect the failure it was written for, a call
/// that keeps blocking for its full timeout. This counts the timeouts the port
/// actually reports and bounds how long the loop takes to stop after
/// cancellation, so a no-op receive fails on the count and a receive that
/// outlives its timeout fails on the latency.
@Test
func udpPortCancellationObservedWithShortReceiveTimeout() async throws {
    let port = try QUICUDPPort()

    let task = Task { () -> Int in
        var timeouts = 0
        while true {
            do {
                _ = try port.receive(timeoutMilliseconds: 10)
            } catch QUICUDPError.timeout {
                timeouts += 1
            } catch {
                Issue.record("receive failed with \(error) while waiting for its timeout")
            }
            if Task.isCancelled {
                return timeouts
            }
        }
    }

    try await Task.sleep(for: .milliseconds(60))
    let cancelledAt = ContinuousClock.now
    task.cancel()
    let timeouts = await task.value
    let stopLatency = ContinuousClock.now - cancelledAt

    #expect(
        timeouts >= 1,
        "the port reported no timeout in 60 ms of 10 ms receives, so the loop was not reading it"
    )
    #expect(
        stopLatency < .milliseconds(500),
        "the loop took \(stopLatency) to observe cancellation; a receive that outlives its 10 ms timeout shows up here"
    )
}

/// F-swift-perf-tests-05: receives must reuse one buffer, not zero-fill a fresh
/// 64 KiB one per datagram, and the reused buffer must still honour the caller's
/// bound.
@Test
func udpReceiveReusesItsBufferAcrossCalls() throws {
    let server = try QUICUDPPort()
    let client = try QUICUDPPort()
    let datagrams = 64
    for index in 0..<datagrams {
        try client.send(
            Data(repeating: UInt8(truncatingIfNeeded: index), count: 32),
            to: server.localEndpoint
        )
    }

    for index in 0..<datagrams {
        let (bytes, _) = try server.receive(maximumBytes: 65_535, timeoutMilliseconds: 1_000)
        #expect(bytes.count == 32)
        #expect(bytes.first == UInt8(truncatingIfNeeded: index))
    }
    #expect(
        server.receiveBufferAllocations <= 1,
        "\(datagrams) receives allocated the buffer \(server.receiveBufferAllocations) times"
    )

    // The buffer is now larger than this request. A datagram that does not fit
    // the caller's bound must still be reported rather than silently truncated to
    // the reused buffer's capacity, and the smaller request must not reallocate.
    try client.send(Data(repeating: 0x5a, count: 32), to: server.localEndpoint)
    #expect(throws: QUICUDPError.self) {
        _ = try server.receive(maximumBytes: 8, timeoutMilliseconds: 1_000)
    }
    #expect(server.receiveBufferAllocations <= 1)
}

/// A datagram larger than the caller's buffer must be reported, not silently truncated.
///
/// The receive path called `recvfrom` without `MSG_TRUNC`, so an oversized datagram came
/// back as a short payload with a valid source and no indication — a QUIC parser would
/// then try to read a packet that was never sent.
@Test
func udpReceiveReportsADatagramLargerThanItsBuffer() throws {
    let server = try QUICUDPPort()
    let client = try QUICUDPPort()

    let oversized = Data(repeating: 0x5a, count: 2_048)
    try client.send(oversized, to: server.localEndpoint)

    // A buffer that cannot hold it is refused rather than truncated.
    #expect(throws: QUICUDPError.self) {
        _ = try server.receive(maximumBytes: 512, timeoutMilliseconds: 1_000)
    }

    // A buffer that can hold it still succeeds, so the check does not reject valid input.
    // The first datagram was consumed by the failed receive, so send again.
    try client.send(oversized, to: server.localEndpoint)
    let (bytes, _) = try server.receive(maximumBytes: 4_096, timeoutMilliseconds: 1_000)
    #expect(bytes.count == oversized.count)
    #expect(bytes == oversized)
}

/// F-swift-line-security-12: `setsockopt` used to have its result discarded, so a
/// socket option that could not be applied surfaced later, if at all, under the
/// wrong operation name. The guard now throws the POSIX error and `init` closes the
/// descriptor before it propagates, like the bind and getsockname guards.
///
/// SO_REUSEADDR does not fail on a fresh socket, so this drives the extracted
/// `applySocketOption` seam with an option number the kernel rejects rather than
/// the socket path end to end.
@Test
func udpPortReportsAFailedSetsockoptUnderItsOwnOperation() throws {
    let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    guard descriptor >= 0 else {
        Issue.record("could not create a probe socket: \(errno)")
        return
    }
    defer { close(descriptor) }

    var value: Int32 = 1
    // The option `init` applies succeeds and returns nothing.
    try QUICUDPPort.applySocketOption(
        descriptor,
        level: SOL_SOCKET,
        name: SO_REUSEADDR,
        value: &value
    )

    // An option the kernel rejects is reported as "setsockopt", not swallowed.
    #expect(throws: QUICUDPError.posix(operation: "setsockopt", code: ENOPROTOOPT)) {
        try QUICUDPPort.applySocketOption(
            descriptor,
            level: SOL_SOCKET,
            name: -1,
            value: &value
        )
    }
}
