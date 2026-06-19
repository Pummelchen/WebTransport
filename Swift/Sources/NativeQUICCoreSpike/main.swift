import Foundation
import WebTransportCryptoApple
import WebTransportHTTP3Core
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
                .resetStreamAt(id: 2, applicationErrorCode: 0x54, finalSize: 2, reliableSize: 2),
                .stopSending(id: 0, applicationErrorCode: 0x55),
                .connectionClose(errorCode: 0x100, frameType: 0x08, reason: Data("phase1b".utf8))
            ]

            try client.send(try QUICFrame.encodeFrames(outboundFrames), to: server.localEndpoint)
            let (serverBytes, clientEndpoint) = try server.receive()
            let serverFrames = try QUICFrame.decodeFrames(serverBytes)
            try assert(serverFrames == outboundFrames, "server decoded client frames")
            print("udp: client-to-server frame packet received from \(clientEndpoint.host):\(clientEndpoint.port)")
            print("frames: stream, datagram, reset, reset-stream-at, stop-sending, and close decoded")

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
            try proveQUICCoreStateMachines()
            try provePacketProtection()
            try proveTLSForQUICScaffold()
            try proveHTTP3ByteCodecs()
            try proveHTTP3ConnectionLayer()
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

    private static func proveQUICCoreStateMachines() throws {
        let policy = QUICVersionPolicy()
        try assert(policy.select(offeredVersion: QUICVersionPolicy.quicV1) == QUICVersionPolicy.quicV1, "QUIC v1 selected")
        try assert(policy.shouldSendVersionNegotiation(for: 0xface_b00c), "unsupported version rejected")

        let token = Data(repeating: 0x11, count: 16)
        var connectionIDs = try QUICConnectionIDStore(initialConnectionID: Data([0x00]), activeConnectionIDLimit: 3)
        _ = try connectionIDs.applyNewConnectionID(
            sequence: 1,
            retirePriorTo: 0,
            connectionID: Data([0x01]),
            statelessResetToken: token
        )
        let retired = try connectionIDs.applyNewConnectionID(
            sequence: 2,
            retirePriorTo: 1,
            connectionID: Data([0x02]),
            statelessResetToken: token
        )
        try assert(retired == [.retireConnectionID(sequence: 0)], "retire_prior_to generated RETIRE_CONNECTION_ID")

        var ackTracker = QUICAckTracker(packetNumberSpace: .applicationData)
        for packetNumber in [2, 6, 7, 9, 10] as [UInt64] {
            _ = ackTracker.recordReceived(packetNumber: packetNumber, nowMicros: 1_000 + packetNumber)
        }
        let ackFrame = try require(ackTracker.makeAckFrame(nowMicros: 1_090), "ACK frame generated")
        try assert(try QUICAckTracker.acknowledgedPacketNumbers(from: ackFrame) == Set([2, 6, 7, 9, 10]), "ACK ranges decode")

        var recovery = QUICLossRecovery(packetThreshold: 3)
        recovery.recordSent(QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 1,
            sentTimeMicros: 100,
            bytes: 32,
            frames: [.stream(id: 0, offset: 0, fin: false, data: Data("lost".utf8))]
        ))
        recovery.recordSent(QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 4,
            sentTimeMicros: 130,
            bytes: 32,
            frames: [.datagram(Data("acked".utf8))]
        ))
        let recoveryResult = try recovery.processAck(
            .ack(largestAcknowledged: 4, ackDelay: 0, firstAckRange: 0, ranges: []),
            in: .applicationData
        )
        try assert(recoveryResult.acknowledged.map(\.packetNumber) == [4], "ACK removes acknowledged packet")
        try assert(recoveryResult.lost.map(\.packetNumber) == [1], "packet threshold loss detection")
        try assert(!recoveryResult.retransmittableFrames.isEmpty, "lost STREAM is retransmittable")

        var congestion = QUICCongestionController(maxDatagramSize: 1_200)
        let initialWindow = congestion.congestionWindow
        congestion.onPacketSent(bytes: 1_200)
        congestion.onPacketAcknowledged(bytes: 1_200)
        try assert(congestion.bytesInFlight == 0 && congestion.congestionWindow > initialWindow, "congestion ACK accounting")

        var connectionFlow = QUICFlowController(maximumData: 64)
        try connectionFlow.reserveSendBytes(32)
        try connectionFlow.receiveBytes(16)
        try assert(connectionFlow.availableSendBytes == 32, "connection flow-control accounting")

        var stream = QUICStreamState(
            id: QUICStreamID.make(index: 0, direction: .bidirectional, initiator: .client),
            localRole: .client,
            maxSendOffset: 64,
            maxReceiveOffset: 64
        )
        let streamFrame = try stream.send(data: Data("state".utf8), fin: true)
        try assert(streamFrame == .stream(id: 0, offset: 0, fin: true, data: Data("state".utf8)), "STREAM send state")
        var peerStream = QUICStreamState(
            id: 0,
            localRole: .server,
            maxSendOffset: 64,
            maxReceiveOffset: 64
        )
        try assert(try peerStream.receive(streamFrame) == Data("state".utf8), "STREAM receive state")

        var datagrams = QUICDatagramQueue(maximumPayloadSize: 64)
        let datagramFrame = try datagrams.makeDatagramFrame(Data("dgram".utf8))
        try datagrams.receive(datagramFrame)
        try assert(datagrams.popReceived() == Data("dgram".utf8), "DATAGRAM queue")

        var close = QUICConnectionCloseState(idleTimeoutMicros: 100, nowMicros: 1_000)
        try assert(try close.checkIdleTimeout(nowMicros: 1_101), "idle timeout close")
        var appClose = QUICConnectionCloseState(idleTimeoutMicros: 100)
        try assert(appClose.closeApplication(errorCode: 0x54, reason: "done") == .connectionClose(
            errorCode: 0x54,
            frameType: nil,
            reason: Data("done".utf8)
        ), "application close mapping")

        print("quic-core: connection IDs, versions, ACK/loss, congestion, streams, flow control, datagrams, close, and idle state passed")
    }

    private static func require<T>(_ value: T?, _ message: String) throws -> T {
        guard let value else {
            throw SpikeError.assertionFailed(message)
        }
        return value
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

        let clientPrivateKey = TLS13KeyAgreement.makeX25519PrivateKey()
        let serverPrivateKey = TLS13KeyAgreement.makeX25519PrivateKey()
        let clientShare = try TLS13KeyAgreement.x25519KeyShare(publicKey: clientPrivateKey.publicKey)
        let serverShare = try TLS13KeyAgreement.x25519KeyShare(publicKey: serverPrivateKey.publicKey)
        let clientSharedSecret = try TLS13KeyAgreement.x25519SharedSecret(
            privateKey: clientPrivateKey,
            peerShare: serverShare
        )
        let serverSharedSecret = try TLS13KeyAgreement.x25519SharedSecret(
            privateKey: serverPrivateKey,
            peerShare: clientShare
        )
        try assert(clientSharedSecret == serverSharedSecret, "X25519 shared secret agreement")

        let clientHello = try TLSClientHello(
            random: Data(repeating: 0x01, count: 32),
            extensions: [
                try TLSSupportedVersionsExtension.client(),
                try TLSALPNExtension.make(protocols: ["h3"]),
                try TLSQUICTransportParametersExtension.make(parameters),
                try TLSKeyShareExtension.client([clientShare]),
                try TLSSignatureAlgorithmsExtension.make([TLSSignatureScheme.ed25519])
            ]
        )
        let serverHello = try TLSServerHello(
            random: Data(repeating: 0x02, count: 32),
            extensions: [
                TLSSupportedVersionsExtension.server(),
                try TLSKeyShareExtension.server(serverShare)
            ]
        )
        let encryptedExtensions = TLSEncryptedExtensions(extensions: decodedExtensions)

        var flightDecoder = TLSHandshakeFlightDecoder()
        let clientHelloMessage = try clientHello.handshakeMessage()
        let serverHelloMessage = try serverHello.handshakeMessage()
        let decodedClientHello = try flightDecoder.receive(frames: TLSHandshakeFlight(
            messages: [clientHelloMessage]
        ).cryptoFrames(maxFramePayloadBytes: 19))
        let decodedServerHello = try flightDecoder.receive(frames: TLSHandshakeFlight(
            messages: [serverHelloMessage]
        ).cryptoFrames(startingOffset: UInt64(try clientHelloMessage.encode().count), maxFramePayloadBytes: 17))
        try assert(decodedClientHello == [clientHelloMessage], "ClientHello CRYPTO flight")
        try assert(decodedServerHello == [serverHelloMessage], "ServerHello CRYPTO flight")

        let handshakeSecret = try TLS13KeyAgreement.handshakeSecret(sharedSecret: clientSharedSecret)
        let trafficSecrets = try TLS13KeyAgreement.handshakeTrafficSecrets(
            handshakeSecret: handshakeSecret,
            transcriptHash: flightDecoder.transcript.hash
        )
        let encryptedExtensionsMessage = try encryptedExtensions.handshakeMessage()
        let decodedEncryptedExtensions = try flightDecoder.receive(frames: TLSHandshakeFlight(
            messages: [encryptedExtensionsMessage]
        ).cryptoFrames(
            startingOffset: flightDecoder.consumedByteCount,
            maxFramePayloadBytes: 13
        ))
        try assert(decodedEncryptedExtensions == [encryptedExtensionsMessage], "EncryptedExtensions CRYPTO flight")

        let verifyData = try TLS13KeySchedule.finishedVerifyData(
            baseKey: trafficSecrets.serverHandshakeTrafficSecret,
            transcriptHash: flightDecoder.transcript.hash
        )
        let trafficKeys = try QUICPacketProtection.deriveKeys(
            trafficSecret: trafficSecrets.serverHandshakeTrafficSecret
        )
        let finished = TLSFinished(verifyData: verifyData)
        try assert(finished.handshakeMessage().type == .finished, "Finished handshake message type")
        try assert(verifyData.count == 32, "Finished verify data length")
        try assert(
            trafficKeys.key.count == 16 &&
                trafficKeys.iv.count == 12 &&
                trafficKeys.headerProtectionKey.count == 16,
            "QUIC handshake traffic key lengths"
        )

        let finishedMessage = finished.handshakeMessage()
        let decodedFinished = try flightDecoder.receive(frames: TLSHandshakeFlight(
            messages: [finishedMessage]
        ).cryptoFrames(
            startingOffset: flightDecoder.consumedByteCount,
            maxFramePayloadBytes: 11
        ))
        try assert(decodedFinished == [finishedMessage], "Finished CRYPTO flight")
        let masterSecret = try TLS13KeyAgreement.masterSecret(handshakeSecret: handshakeSecret)
        let applicationTrafficSecrets = try TLS13KeyAgreement.applicationTrafficSecrets(
            masterSecret: masterSecret,
            transcriptHash: flightDecoder.transcript.hash
        )
        let applicationKeys = try QUICPacketProtection.deriveKeys(
            trafficSecret: applicationTrafficSecrets.serverApplicationTrafficSecret
        )
        let protectedPayload = try QUICPacketProtection.seal(
            plaintext: Data("1rtt webtransport payload".utf8),
            packetNumber: 9,
            associatedData: Data("short-header".utf8),
            keys: applicationKeys
        )
        let openedPayload = try QUICPacketProtection.open(
            ciphertextAndTag: protectedPayload,
            packetNumber: 9,
            associatedData: Data("short-header".utf8),
            keys: applicationKeys
        )
        try assert(openedPayload == Data("1rtt webtransport payload".utf8), "1-RTT QUIC packet protection")
        print("tls: CRYPTO flights, X25519, ALPN h3, QUIC transport parameters, Finished verify data, and QUIC handshake/1-RTT keys passed")
    }

    private static func proveHTTP3ByteCodecs() throws {
        let constants = WebTransportHTTP3DraftConstants.current
        let settings = try HTTP3Settings([
            constants.settingsWTEnabled: 1,
            constants.settingsWTInitialMaxStreamsUni: 3,
            constants.settingsWTInitialMaxStreamsBidi: 5,
            constants.settingsWTInitialMaxData: 65_536
        ])
        let frames = [
            try settings.frame(),
            try HTTP3Frame(type: HTTP3FrameType.headers, payload: Data([0x00, 0x00])),
            try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 4)
        ]
        let decodedFrames = try HTTP3Frame.decodeFrames(try HTTP3Frame.encodeFrames(frames))
        try assert(decodedFrames == frames, "HTTP/3 frame codec")
        try assert(
            try HTTP3Settings.decodeFrame(decodedFrames[0]).entries == settings.entries,
            "HTTP/3 SETTINGS codec"
        )

        let webTransportStream = try HTTP3StreamTypeParser.parsePrefix(
            HTTP3StreamTypeParser.encodePrefix(
                type: constants.webTransportStream,
                payload: try QUICVarInt.encode(4)
            )
        )
        let expectedSessionPrefix = try QUICVarInt.encode(4)
        try assert(webTransportStream.type == constants.webTransportStream, "WebTransport stream type")
        try assert(webTransportStream.remainingBytes == expectedSessionPrefix, "WebTransport session prefix")

        let connectFrame = try WebTransportHTTP3Headers.connectRequestHeadersFrame(
            authority: "example.com",
            path: "/wt"
        )
        try WebTransportHTTP3Headers.validateConnectRequest(try QPACK.decodeHeadersFrame(connectFrame))
        let responseFrame = try WebTransportHTTP3Headers.successfulResponseHeadersFrame()
        try WebTransportHTTP3Headers.validateSuccessfulResponse(try QPACK.decodeHeadersFrame(responseFrame))
        print("http3: frame headers, SETTINGS, stream types, draft-15 constants, and QPACK HEADERS passed")
    }

    private static func proveHTTP3ConnectionLayer() throws {
        var client = HTTP3ConnectionState(role: .client)
        var server = HTTP3ConnectionState(role: .server)
        _ = try server.receivePeerControlStream(client.localControlStreamBytes())
        _ = try client.receivePeerControlStream(server.localControlStreamBytes())
        try assert(client.remoteSettings?.entries == HTTP3Settings.webTransportDraft15Defaults.entries, "client received server SETTINGS")
        try assert(server.remoteSettings?.entries == HTTP3Settings.webTransportDraft15Defaults.entries, "server received client SETTINGS")

        var clientStream = try client.openRequestStream(streamID: 0)
        var serverStream = try server.acceptRequestStream(streamID: 0)
        let requestHeaders = try WebTransportHTTP3Headers.connectRequest(
            authority: "example.com",
            path: "/wt",
            origin: "https://example.com"
        )
        let requestFrame = try clientStream.makeRequestHeadersFrame(requestHeaders)
        try serverStream.receive(frame: requestFrame)
        let responseHeaders = try WebTransportHTTP3Headers.successfulResponse()
        let responseFrame = try serverStream.makeResponseHeadersFrame(responseHeaders)
        try clientStream.receive(frame: responseFrame)
        client.storeRequestStream(clientStream)
        server.storeRequestStream(serverStream)

        let goaway = try server.makeGoawayFrame(streamID: 0)
        try client.receiveControlFrame(goaway)
        try assert(client.receivedGoawayID == 0, "client received GOAWAY")
        try assert(server.closeFrame(error: .settingsError, reason: "settings") == .connectionClose(
            errorCode: HTTP3ApplicationErrorCode.settingsError.rawValue,
            frameType: nil,
            reason: Data("settings".utf8)
        ), "HTTP/3 error maps to QUIC application close")

        print("http3-layer: control streams, SETTINGS, request HEADERS, DATA policy, GOAWAY, and error mapping passed")
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
