import Foundation
import WebTransportCryptoApple
import WebTransportQUICCore
import WebTransportTLSCore
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
            try provePacketProtection()
            try proveTLSForQUICScaffold()
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

    private static func provePacketProtection() throws {
        let trafficSecret = Data(repeating: 0x42, count: 32)
        let keys = try QUICPacketProtection.deriveKeys(trafficSecret: trafficSecret)
        let associatedData = Data("phase1b-handshake-header".utf8)
        let plaintext = try QUICFrame.encodeFrames([
            .stream(id: 0, offset: 0, fin: false, data: Data("protected-stream".utf8)),
            .datagram(Data("protected-datagram".utf8))
        ])
        let sealed = try QUICPacketProtection.seal(
            plaintext: plaintext,
            packetNumber: 7,
            associatedData: associatedData,
            keys: keys
        )
        let opened = try QUICPacketProtection.open(
            ciphertextAndTag: sealed,
            packetNumber: 7,
            associatedData: associatedData,
            keys: keys
        )
        try assert(opened == plaintext, "packet protection opened sealed payload")

        let mask = try QUICPacketProtection.headerProtectionMask(
            sample: Data(repeating: 0x11, count: 16),
            headerProtectionKey: keys.headerProtectionKey
        )
        try assert(mask.count == 5, "header protection mask is five bytes")
        print("protection: Handshake/1-RTT style AEAD seal/open and header mask passed")
    }

    private static func proveTLSForQUICScaffold() throws {
        var parameters = QUICTransportParameters()
        try parameters.setInteger(1_200, for: QUICTransportParameterID.maxDatagramFrameSize)
        let extensionList = try TLSExtension.encodeList([
            TLSALPNExtension.make(protocols: ["h3"]),
            TLSQUICTransportParametersExtension.make(parameters)
        ])
        let decodedExtensions = try TLSExtension.decodeList(extensionList)
        try assert(decodedExtensions.count == 2, "decoded TLS extensions")

        let clientHello = try TLSClientHello(
            random: Data(repeating: 0x01, count: 32),
            extensions: [
                try TLSSupportedVersionsExtension.client(),
                try TLSALPNExtension.make(protocols: ["h3"]),
                try TLSQUICTransportParametersExtension.make(parameters),
                try TLSKeyShareExtension.client([
                    TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x11, count: 32))
                ]),
                try TLSSignatureAlgorithmsExtension.make([TLSSignatureScheme.ed25519])
            ]
        )
        let serverHello = try TLSServerHello(
            random: Data(repeating: 0x02, count: 32),
            extensions: [
                TLSSupportedVersionsExtension.server(),
                try TLSKeyShareExtension.server(
                    TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x22, count: 32))
                )
            ]
        )
        let encryptedExtensions = TLSEncryptedExtensions(extensions: decodedExtensions)

        var transcript = TLS13Transcript()
        try transcript.append(clientHello.handshakeMessage())
        try transcript.append(serverHello.handshakeMessage())
        try transcript.append(encryptedExtensions.handshakeMessage())

        let baseSecret = Data(repeating: 0x33, count: 32)
        let trafficSecret = try TLS13KeySchedule.deriveSecret(
            secret: baseSecret,
            label: "c hs traffic",
            transcriptHash: transcript.hash
        )
        let verifyData = try TLS13KeySchedule.finishedVerifyData(
            baseKey: trafficSecret,
            transcriptHash: transcript.hash
        )
        let trafficKeys = try TLS13KeySchedule.trafficKeys(trafficSecret: trafficSecret)
        let finished = TLSFinished(verifyData: verifyData)
        try assert(finished.handshakeMessage().type == .finished, "Finished handshake message type")
        try assert(verifyData.count == 32, "Finished verify data length")
        try assert(trafficKeys.key.count == 16 && trafficKeys.iv.count == 12, "TLS traffic key lengths")
        print("tls: ALPN h3, QUIC transport parameters, transcript hash, Finished verify data, and traffic keys passed")
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
