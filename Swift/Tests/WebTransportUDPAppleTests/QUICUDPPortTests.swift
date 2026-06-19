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
        .datagram(Data("dgram".utf8))
    ]
    try client.send(try QUICFrame.encodeFrames(frames), to: server.localEndpoint)

    let (bytes, endpoint) = try server.receive(timeoutMilliseconds: 1_000)
    #expect(endpoint.port == client.localEndpoint.port)
    #expect(try QUICFrame.decodeFrames(bytes) == frames)
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
