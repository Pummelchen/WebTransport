import Foundation
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
    let server = try WebTransportNetworkProbeServer(bindPort: 0)
    let task = Task.detached {
        try server.serveOne(timeoutMilliseconds: 2_000)
    }

    let client = WebTransportNetworkProbeClient()
    let clientResult = try client.run(
        to: server.localEndpoint,
        message: "runtime",
        timeoutMilliseconds: 2_000
    )
    let serverResult = try await task.value

    #expect(clientResult.message == "runtime")
    #expect(serverResult.message == "runtime")
    #expect(clientResult.remoteEndpoint.port == server.localEndpoint.port)
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

    let serverPacket = try WebTransportQUICPacketProbeCodec.encodeServerInitial(
        request: decodedRequest,
        message: decodedRequest.message
    )
    #expect(serverPacket.range(of: Data("WT-QUIC-SERVER-FLIGHT".utf8)) == nil)
    #expect(try WebTransportQUICPacketProbeCodec.decodeServerInitial(serverPacket) == "hello")

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
            .crypto(offset: 0, data: try TLSHandshakeMessage(
                type: .clientHello,
                body: Data("WT-QUIC-CLIENT-FLIGHT\0one".utf8)
            ).encode()),
            .crypto(offset: 0, data: try TLSHandshakeMessage(
                type: .clientHello,
                body: Data("WT-QUIC-CLIENT-FLIGHT\0two".utf8)
            ).encode()),
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
        _ = try WebTransportQUICPacketProbeCodec.decodeServerInitial(mismatchedServerInitial)
    }
}

@Test
func quicPacketProbeReassemblesOutOfOrderCryptoFragments() throws {
    let handshake = TLSHandshakeMessage(
        type: .clientHello,
        body: Data("WT-QUIC-CLIENT-FLIGHT\0fragmented".utf8)
    )
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
func quicPacketProbeClientServerExchangeOverUDP() async throws {
    let server = try WebTransportQUICPacketProbeServer(bindPort: 0)
    let task = Task.detached {
        try server.serveOne(timeoutMilliseconds: 2_000)
    }

    let client = WebTransportQUICPacketProbeClient()
    let clientResult = try client.run(
        to: server.localEndpoint,
        message: "packet-runtime",
        timeoutMilliseconds: 2_000
    )
    let serverResult = try await task.value

    #expect(clientResult.transport == .packet)
    #expect(serverResult.transport == .packet)
    #expect(clientResult.message == "packet-runtime")
    #expect(serverResult.message == "packet-runtime")
    #expect(clientResult.remoteEndpoint.port == server.localEndpoint.port)
    #expect(serverResult.remoteEndpoint.port == clientResult.localEndpoint.port)
}

@Test
func networkEndpointParserRejectsMalformedValues() throws {
    #expect(try WebTransportNetworkEndpoint.parse("127.0.0.1:4433") == WebTransportNetworkEndpoint(
        host: "127.0.0.1",
        port: 4433
    ))
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkEndpoint.parse("127.0.0.1")
    }
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkEndpoint.parse("127.0.0.1:not-a-port")
    }
    #expect(try WebTransportNetworkProbeTransport.parse("packet") == .packet)
    #expect(try WebTransportNetworkProbeTransport.parse("frame") == .frame)
    #expect(throws: Error.self) {
        _ = try WebTransportNetworkProbeTransport.parse("unknown")
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
