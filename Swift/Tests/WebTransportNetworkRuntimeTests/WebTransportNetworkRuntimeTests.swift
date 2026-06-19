import Foundation
import Darwin
import Testing
@testable import WebTransportNetworkRuntime
import WebTransportQUICCore
import WebTransportTLSCore

@Test
func networkProbeCodecRoundTripsAndRejectsMalformedPackets() throws {
    let probe = try WebTransportNetworkProbeCodec.encodeProbePacket(message: "hello")
    #expect(try WebTransportNetworkProbeCodec.decodeProbePacket(probe) == "hello")

    let ack = try WebTransportNetworkProbeCodec.encodeAckPacket(message: "hello")
    #expect(try WebTransportNetworkProbeCodec.decodeAckPacket(ack) == "hello")

    #expect(throws: Error.self) {
        _ = try WebTransportNetworkProbeCodec.decodeProbePacket(ack)
    }
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkProbeCodec.decodeProbePacket(try QUICFrame.encodeFrames([
            .stream(id: 0, offset: 0, fin: false, data: Data("not a probe".utf8))
        ]))
    }
}

@Test
func networkProbeClientServerExchangeOverUDP() async throws {
    let (clientResult, serverResult, localPort) = try await WebTransportRuntimeLoopbackGate.withLock(label: #function) {
        let server = try WebTransportNetworkProbeServer(bindPort: 0)
        let task = Task.detached {
            try server.serveOne(timeoutMilliseconds: 15_000)
        }
        try await Task.sleep(for: .milliseconds(25))

        let client = WebTransportNetworkProbeClient()
        let clientResult = try client.run(
            to: server.localEndpoint,
            message: "runtime",
            timeoutMilliseconds: 15_000
        )
        let serverResult = try await task.value
        return (clientResult, serverResult, server.localEndpoint.port)
    }

    #expect(clientResult.message == "runtime")
    #expect(serverResult.message == "runtime")
    #expect(clientResult.remoteEndpoint.port == localPort)
    #expect(serverResult.remoteEndpoint.port == clientResult.localEndpoint.port)
}

@Test
func quicPacketProbeCodecUsesProtectedInitialPacketsAndRejectsMalformedPackets() throws {
    let clientPacket = try WebTransportQUICPacketProbeCodec.encodeClientInitial(message: "hello")
    #expect(clientPacket.count >= WebTransportQUICPacketProbeCodec.minimumInitialDatagramBytes)
    #expect(clientPacket.range(of: Data("WT-QUIC-CLIENT-FLIGHT".utf8)) == nil)

    let decodedRequest = try WebTransportQUICPacketProbeCodec.decodeClientInitial(clientPacket)
    #expect(decodedRequest.message == "hello")
    #expect(decodedRequest.packetNumber == 0)
    #expect(decodedRequest.handshakeMessages.map(\.type) == [.clientHello])
    let clientHello = try TLSClientHello.decode(try #require(decodedRequest.handshakeMessages.first).body)
    #expect(String(data: clientHello.legacySessionID, encoding: .utf8) == "hello")
    let clientALPN = try #require(clientHello.extensions.first {
        $0.type == TLSExtensionType.applicationLayerProtocolNegotiation.rawValue
    })
    #expect(try TLSALPNExtension.protocols(from: clientALPN.data) == ["h3"])
    let clientTransportParameters = try #require(clientHello.extensions.first {
        $0.type == TLSExtensionType.quicTransportParameters.rawValue
    })
    #expect(try TLSQUICTransportParametersExtension.parameters(from: clientTransportParameters.data)
        .integer(for: QUICTransportParameterID.maxDatagramFrameSize) == 1_200)

    let serverPacket = try WebTransportQUICPacketProbeCodec.encodeServerInitial(
        request: decodedRequest,
        message: decodedRequest.message
    )
    #expect(serverPacket.range(of: Data("WT-QUIC-SERVER-FLIGHT".utf8)) == nil)
    let handshakeContext = try WebTransportQUICPacketProbeCodec.decodeServerInitialContext(
        serverPacket,
        request: decodedRequest
    )
    #expect(handshakeContext.message == "hello")
    #expect(handshakeContext.request == decodedRequest)
    #expect(handshakeContext.serverHandshakeMessages.map(\.type) == [
        .serverHello,
        .encryptedExtensions,
        .certificate,
        .certificateVerify,
        .finished
    ])
    let decodedServerPacket = try QUICInitialPacketProtection.open(
        serverPacket,
        keyPhase: .server,
        initialSecretConnectionID: decodedRequest.destinationConnectionID,
        parsedHeader: try QUICInitialPacketProtection.parseProtectedLongHeader(serverPacket)
    )
    let serverCryptoFrames = try QUICFrame.decodeFrames(decodedServerPacket.payload).compactMap { frame -> QUICFrame? in
        guard case .crypto = frame else {
            return nil
        }
        return frame
    }
    var serverFlightDecoder = TLSHandshakeFlightDecoder()
    let serverMessages = try serverFlightDecoder.receive(frames: serverCryptoFrames)
    #expect(serverMessages.map(\.type) == [
        .serverHello,
        .encryptedExtensions,
        .certificate,
        .certificateVerify,
        .finished
    ])
    #expect(try TLSCertificate.decode(serverMessages[2].body).entries.count == 1)
    #expect(try TLSCertificateVerify.decode(serverMessages[3].body).signature.count == 64)
    #expect(TLSFinished.decode(serverMessages[4].body).verifyData.count == 32)

    var invalidCertificateVerifyMessages = serverMessages
    invalidCertificateVerifyMessages[3] = try TLSCertificateVerify(
        algorithm: TLSSignatureScheme.ed25519,
        signature: Data(repeating: 0xaa, count: 64)
    ).handshakeMessage()
    let invalidCertificateVerifyPacket = try protectedServerInitial(
        request: decodedRequest,
        messages: invalidCertificateVerifyMessages
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeServerInitial(
            invalidCertificateVerifyPacket,
            request: decodedRequest
        )
    }

    var invalidFinishedMessages = serverMessages
    invalidFinishedMessages[4] = TLSFinished(verifyData: Data(repeating: 0xbb, count: 32)).handshakeMessage()
    let invalidFinishedPacket = try protectedServerInitial(
        request: decodedRequest,
        messages: invalidFinishedMessages
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeServerInitial(
            invalidFinishedPacket,
            request: decodedRequest
        )
    }

    let applicationRequestPacket = try WebTransportQUICPacketProbeCodec.encodeClientApplicationRequest(
        handshakeContext: handshakeContext,
        message: "hello"
    )
    #expect(applicationRequestPacket.range(of: Data("hello".utf8)) == nil)
    let applicationRequest = try WebTransportQUICPacketProbeCodec.decodeClientApplicationRequest(
        applicationRequestPacket,
        handshakeContext: handshakeContext
    )
    #expect(applicationRequest.message == "hello")
    #expect(applicationRequest.packetNumber == 1)
    #expect(applicationRequest.requestHeaders.contains {
        $0.name == ":protocol" && $0.value == "webtransport-h3"
    })

    let applicationResponsePacket = try WebTransportQUICPacketProbeCodec.encodeServerApplicationResponse(
        handshakeContext: handshakeContext,
        message: applicationRequest.message
    )
    #expect(applicationResponsePacket.range(of: Data("hello".utf8)) == nil)
    #expect(try WebTransportQUICPacketProbeCodec.decodeServerApplicationResponse(
        applicationResponsePacket,
        handshakeContext: handshakeContext
    ) == "hello")

    let mismatchedHandshakeContext = try WebTransportQUICPacketProbeCodec.serverHandshakeContext(
        request: decodedRequest,
        message: "other"
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientApplicationRequest(
            applicationRequestPacket,
            handshakeContext: mismatchedHandshakeContext
        )
    }
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeServerApplicationResponse(
            applicationResponsePacket,
            handshakeContext: mismatchedHandshakeContext
        )
    }

    var truncated = clientPacket
    truncated.removeLast()
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(truncated)
    }
    var tamperedCiphertext = clientPacket
    tamperedCiphertext[tamperedCiphertext.count - 1] ^= 0x01
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(tamperedCiphertext)
    }
    var tamperedHeader = clientPacket
    tamperedHeader[5] ^= 0x01
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(tamperedHeader)
    }

    let unexpectedFramePacket = try protectedClientInitial(
        destinationConnectionID: decodedRequest.destinationConnectionID,
        sourceConnectionID: decodedRequest.sourceConnectionID,
        frames: [
            .stream(id: 0, offset: 0, fin: false, data: Data("not allowed".utf8))
        ],
        padToMinimumInitialSize: true
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(unexpectedFramePacket)
    }

    let shortClientInitial = try protectedClientInitial(
        destinationConnectionID: decodedRequest.destinationConnectionID,
        sourceConnectionID: decodedRequest.sourceConnectionID,
        frames: [
            .crypto(offset: 0, data: Data("WT-QUIC-CLIENT-FLIGHT\0short".utf8)),
            .ping
        ],
        padToMinimumInitialSize: false
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(shortClientInitial)
    }

    let duplicateCryptoBytes = try protectedClientInitial(
        destinationConnectionID: decodedRequest.destinationConnectionID,
        sourceConnectionID: decodedRequest.sourceConnectionID,
        frames: [
            .crypto(offset: 0, data: try WebTransportQUICPacketProbeCodec.makeClientHelloHandshakeMessage(message: "one").encode()),
            .crypto(offset: 0, data: try WebTransportQUICPacketProbeCodec.makeClientHelloHandshakeMessage(message: "two").encode()),
            .ping
        ],
        padToMinimumInitialSize: true
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(duplicateCryptoBytes)
    }

    let mismatchedServerInitial = try QUICInitialPacketProtection.seal(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: Data([0x01, 0x02, 0x03, 0x04]),
        sourceConnectionID: decodedRequest.destinationConnectionID,
        token: Data(),
        packetNumber: 0,
        packetNumberLength: 2,
        plaintextPayload: try QUICFrame.encodeFrames([
            .ack(largestAcknowledged: decodedRequest.packetNumber, ackDelay: 0, firstAckRange: 0, ranges: []),
            .crypto(offset: 0, data: Data("WT-QUIC-SERVER-FLIGHT\0hello".utf8))
        ]),
        keyPhase: .server,
        initialSecretConnectionID: decodedRequest.destinationConnectionID
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeServerInitial(
            mismatchedServerInitial,
            request: decodedRequest
        )
    }

    var tamperedApplication = applicationRequestPacket
    tamperedApplication[tamperedApplication.count - 1] ^= 0x01
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientApplicationRequest(
            tamperedApplication,
            handshakeContext: handshakeContext
        )
    }
}

@Test
func quicPacketProbeReassemblesOutOfOrderCryptoFragments() throws {
    let handshake = try WebTransportQUICPacketProbeCodec.makeClientHelloHandshakeMessage(message: "fragmented")
    let frames = try TLSHandshakeFlight(messages: [handshake])
        .cryptoFrames(maxFramePayloadBytes: 6)
        .reversed()
    let packet = try protectedClientInitial(
        destinationConnectionID: Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65]),
        sourceConnectionID: Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e]),
        frames: Array(frames) + [.ping],
        padToMinimumInitialSize: true
    )

    let decoded = try WebTransportQUICPacketProbeCodec.decodeClientInitial(packet)
    #expect(decoded.message == "fragmented")
    #expect(decoded.handshakeMessages == [handshake])
}

@Test
func quicPacketProbeRejectsWrongALPNAndTransportParameters() throws {
    let wrongALPN = try protectedClientInitial(
        destinationConnectionID: Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65]),
        sourceConnectionID: Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e]),
        frames: try TLSHandshakeFlight(messages: [
            clientHelloForValidationTest(message: "wrong-alpn", alpn: "h2", maxDatagramFrameSize: 1_200)
        ]).cryptoFrames(maxFramePayloadBytes: 8) + [.ping],
        padToMinimumInitialSize: true
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(wrongALPN)
    }

    let wrongTransportParameter = try protectedClientInitial(
        destinationConnectionID: Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65]),
        sourceConnectionID: Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e]),
        frames: try TLSHandshakeFlight(messages: [
            clientHelloForValidationTest(message: "small-datagram", alpn: "h3", maxDatagramFrameSize: 1_199)
        ]).cryptoFrames(maxFramePayloadBytes: 8) + [.ping],
        padToMinimumInitialSize: true
    )
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(wrongTransportParameter)
    }
}

@Test
func quicPacketProbeClientServerExchangeOverUDP() async throws {
    let (clientResult, serverResult, localPort) = try await WebTransportRuntimeLoopbackGate.withLock(label: #function) {
        let server = try WebTransportQUICPacketProbeServer(bindPort: 0)
        let task = Task.detached {
            try server.serveOne(timeoutMilliseconds: 15_000)
        }
        try await Task.sleep(for: .milliseconds(25))

        let client = WebTransportQUICPacketProbeClient()
        let clientResult = try client.run(
            to: server.localEndpoint,
            message: "packet-runtime",
            timeoutMilliseconds: 15_000
        )
        let serverResult = try await task.value
        return (clientResult, serverResult, server.localEndpoint.port)
    }

    #expect(clientResult.transport == .packet)
    #expect(serverResult.transport == .packet)
    #expect(clientResult.sessionEstablished)
    #expect(serverResult.sessionEstablished)
    #expect(clientResult.message == "packet-runtime")
    #expect(serverResult.message == "packet-runtime")
    #expect(clientResult.remoteEndpoint.port == localPort)
    #expect(serverResult.remoteEndpoint.port == clientResult.localEndpoint.port)
}

@Test
func networkEndpointParserRejectsMalformedValues() throws {
    #expect(try WebTransportNetworkEndpoint.parse("127.0.0.1:4433") == WebTransportNetworkEndpoint(
        host: "127.0.0.1",
        port: 4433
    ))
    #expect(try WebTransportNetworkEndpoint.parse("[::1]:4433") == WebTransportNetworkEndpoint(
        host: "::1",
        port: 4433
    ))
    #expect(WebTransportNetworkEndpoint(host: "::1", port: 4433).commandLineValue == "[::1]:4433")
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkEndpoint.parse("127.0.0.1")
    }
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkEndpoint.parse("127.0.0.1:not-a-port")
    }
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkEndpoint.parse("::1:4433")
    }
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkEndpoint.parse("[::1]")
    }
    #expect(try WebTransportNetworkTransport.parse("packet") == .packet)
    #expect(try WebTransportNetworkTransport.parse("frame") == .frame)
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkTransport.parse("unknown")
    }
}

private func protectedClientInitial(
    destinationConnectionID: Data,
    sourceConnectionID: Data,
    frames: [QUICFrame],
    padToMinimumInitialSize: Bool
) throws -> Data {
    var payload = try QUICFrame.encodeFrames(frames)
    var encoded = try QUICInitialPacketProtection.seal(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: destinationConnectionID,
        sourceConnectionID: sourceConnectionID,
        token: Data(),
        packetNumber: 0,
        packetNumberLength: 2,
        plaintextPayload: payload,
        keyPhase: .client,
        initialSecretConnectionID: destinationConnectionID
    )
    while padToMinimumInitialSize && encoded.count < WebTransportQUICPacketProbeCodec.minimumInitialDatagramBytes {
        payload.append(0x00)
        encoded = try QUICInitialPacketProtection.seal(
            packetType: .initial,
            version: WebTransportQUICPacketProbeCodec.quicVersion,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: Data(),
            packetNumber: 0,
            packetNumberLength: 2,
            plaintextPayload: payload,
            keyPhase: .client,
            initialSecretConnectionID: destinationConnectionID
        )
    }
    return encoded
}

private func protectedServerInitial(
    request: WebTransportQUICPacketProbeRequest,
    messages: [TLSHandshakeMessage]
) throws -> Data {
    let frames = [.ack(largestAcknowledged: request.packetNumber, ackDelay: 0, firstAckRange: 0, ranges: [])]
        + (try TLSHandshakeFlight(messages: messages).cryptoFrames(maxFramePayloadBytes: 9))
    return try QUICInitialPacketProtection.seal(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: request.sourceConnectionID,
        sourceConnectionID: request.destinationConnectionID,
        token: Data(),
        packetNumber: 0,
        packetNumberLength: 2,
        plaintextPayload: try QUICFrame.encodeFrames(frames),
        keyPhase: .server,
        initialSecretConnectionID: request.destinationConnectionID
    )
}

private func clientHelloForValidationTest(
    message: String,
    alpn: String,
    maxDatagramFrameSize: UInt64
) throws -> TLSHandshakeMessage {
    var parameters = QUICTransportParameters()
    try parameters.setInteger(maxDatagramFrameSize, for: QUICTransportParameterID.maxDatagramFrameSize)
    try parameters.setInteger(1_200, for: QUICTransportParameterID.maxUDPPayloadSize)
    parameters[QUICTransportParameterID.initialSourceConnectionID] = Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e])

    return try TLSClientHello(
        random: Data(repeating: 0x43, count: 32),
        legacySessionID: Data(message.utf8),
        extensions: [
            try TLSSupportedVersionsExtension.client(),
            try TLSALPNExtension.make(protocols: [alpn]),
            try TLSQUICTransportParametersExtension.make(parameters),
            try TLSKeyShareExtension.client([
                TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x11, count: 32))
            ]),
            try TLSSignatureAlgorithmsExtension.make([TLSSignatureScheme.ed25519])
        ]
    ).handshakeMessage()
}

private enum WebTransportRuntimeLoopbackGate {
    private static let lockPath = "/tmp/webtransport-loopback-tests.dirlock"
    private static let ownerFile = "owner.txt"
    private static let maximumWait: TimeInterval = 180

    static func withLock<T>(label: String, _ body: () async throws -> T) async throws -> T {
        try await acquireAsync(label: label)
        defer {
            release()
        }
        return try await body()
    }

    private static func acquireAsync(label: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try acquireBlocking(label: label)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func acquireBlocking(label: String) throws {
        let deadline = Date().addingTimeInterval(maximumWait)
        while true {
            if Darwin.mkdir(lockPath, S_IRWXU) == 0 {
                try writeOwner(label)
                return
            }
            guard errno == EEXIST else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            if Date() >= deadline {
                throw NSError(
                    domain: "WebTransportRuntimeLoopbackGate",
                    code: Int(ETIMEDOUT),
                    userInfo: [NSLocalizedDescriptionKey: "Timed out waiting for loopback lock held by \(readOwner())"]
                )
            }
            usleep(10_000)
        }
    }

    private static func writeOwner(_ label: String) throws {
        let owner = "\(label) pid=\(getpid())"
        try owner.write(
            toFile: "\(lockPath)/\(ownerFile)",
            atomically: true,
            encoding: .utf8
        )
    }

    private static func readOwner() -> String {
        (try? String(contentsOfFile: "\(lockPath)/\(ownerFile)", encoding: .utf8)) ?? "unknown owner"
    }

    private static func release() {
        _ = Darwin.unlink("\(lockPath)/\(ownerFile)")
        _ = Darwin.rmdir(lockPath)
    }
}
