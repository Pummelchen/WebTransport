import Foundation
import WebTransportQUICCore
import WebTransportUDPApple

#if !arch(arm64)
#error("WebTransport Swift supports Apple Silicon arm64 only. Intel/x86_64 builds are unsupported.")
#endif

@available(macOS 26.0, *)
@main
enum NativeQUICCoreSpike {
    static func main() {
        setbuf(stdout, nil)

        do {
            let server = try QUICUDPPort()
            let client = try QUICUDPPort()

            let outboundFrames: [QUICFrame] = [
                .stream(id: 0, offset: 0, fin: false, data: Data("client-bidi".utf8)),
                .stream(id: 2, offset: 0, fin: true, data: Data([0x54, 0x00])),
                .datagram(Data("client-datagram".utf8)),
                .resetStream(id: 0, applicationErrorCode: 0x54, finalSize: 11),
                .stopSending(id: 0, applicationErrorCode: 0x55),
                .connectionClose(errorCode: 0x100, frameType: 0x08, reason: Data("phase1b".utf8))
            ]

            try client.send(try QUICFrame.encodeFrames(outboundFrames), to: server.localEndpoint)
            let (serverBytes, clientEndpoint) = try server.receive()
            let serverFrames = try QUICFrame.decodeFrames(serverBytes)
            try assert(serverFrames == outboundFrames, "server decoded client frames")
            print("udp: client-to-server frame packet received from \(clientEndpoint.host):\(clientEndpoint.port)")
            print("frames: stream, datagram, reset, stop-sending, and close decoded")

            let responseFrames: [QUICFrame] = [
                .stream(id: 1, offset: 0, fin: false, data: Data("server-bidi".utf8)),
                .datagram(Data("server-datagram".utf8)),
                .handshakeDone
            ]
            try server.send(try QUICFrame.encodeFrames(responseFrames), to: client.localEndpoint)
            let (clientBytes, _) = try client.receive()
            let clientFrames = try QUICFrame.decodeFrames(clientBytes)
            try assert(clientFrames == responseFrames, "client decoded server frames")
            print("udp: server-to-client frame packet received")
            print("phase1b: native QUIC core frame exchange over Apple UDP passed without security prompts")
        } catch {
            fputs("NativeQUICCoreSpike failed: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    private static func assert(_ condition: Bool, _ message: String) throws {
        if !condition {
            throw SpikeError.assertionFailed(message)
        }
    }
}

private enum SpikeError: Error, CustomStringConvertible {
    case assertionFailed(String)

    var description: String {
        switch self {
        case .assertionFailed(let message):
            "assertion failed: \(message)"
        }
    }
}
