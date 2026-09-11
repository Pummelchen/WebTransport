import Foundation
import Testing
import WebTransportQUICCore
import WebTransportUDPApple

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

@Test
func udpPortCancellationObservedWithShortReceiveTimeout() async throws {
    let port = try QUICUDPPort()

    let task = Task { () -> Bool in
        var looped = false
        while true {
            do {
                _ = try port.receive(timeoutMilliseconds: 10)
            } catch {
                // expected for timeout
            }
            if Task.isCancelled {
                looped = true
                break
            }
        }
        return looped
    }

    try await Task.sleep(for: .milliseconds(60))
    task.cancel()
    let observedCancellation = await task.value
    #expect(observedCancellation)
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
