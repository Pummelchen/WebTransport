import Foundation
import Testing
import WebTransportNetworkRuntime
import WebTransportQUICCore

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
func quicPacketProbeCodecUsesInitialPacketsAndRejectsMalformedPackets() throws {
    let clientPacket = try WebTransportQUICPacketProbeCodec.encodeClientInitial(message: "hello")
    #expect(clientPacket.count >= WebTransportQUICPacketProbeCodec.minimumInitialDatagramBytes)

    let decodedRequest = try WebTransportQUICPacketProbeCodec.decodeClientInitial(clientPacket)
    #expect(decodedRequest.message == "hello")
    #expect(decodedRequest.packetNumber == 0)

    let serverPacket = try WebTransportQUICPacketProbeCodec.encodeServerInitial(
        request: decodedRequest,
        message: decodedRequest.message
    )
    #expect(try WebTransportQUICPacketProbeCodec.decodeServerInitial(serverPacket) == "hello")

    var truncated = clientPacket
    truncated.removeLast()
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(truncated)
    }

    let unexpectedFramePacket = try QUICLongHeaderPacket(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: decodedRequest.destinationConnectionID,
        sourceConnectionID: decodedRequest.sourceConnectionID,
        packetNumber: 0,
        packetNumberLength: 2,
        payload: try QUICFrame.encodeFrames([
            .stream(id: 0, offset: 0, fin: false, data: Data("not allowed".utf8))
        ])
    ).encode()
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(unexpectedFramePacket)
    }

    let shortClientInitial = try QUICLongHeaderPacket(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: decodedRequest.destinationConnectionID,
        sourceConnectionID: decodedRequest.sourceConnectionID,
        packetNumber: 0,
        packetNumberLength: 2,
        payload: try QUICFrame.encodeFrames([
            .crypto(offset: 0, data: Data("WT-QUIC-PROBE\0short".utf8)),
            .ping
        ])
    ).encode()
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(shortClientInitial)
    }

    var duplicatePayload = try QUICFrame.encodeFrames([
        .crypto(offset: 0, data: Data("WT-QUIC-PROBE\0one".utf8)),
        .crypto(offset: 0, data: Data("WT-QUIC-PROBE\0two".utf8)),
        .ping
    ])
    var duplicateCryptoPacket = QUICLongHeaderPacket(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: decodedRequest.destinationConnectionID,
        sourceConnectionID: decodedRequest.sourceConnectionID,
        packetNumber: 0,
        packetNumberLength: 2,
        payload: duplicatePayload
    )
    var duplicateCryptoBytes = try duplicateCryptoPacket.encode()
    while duplicateCryptoBytes.count < WebTransportQUICPacketProbeCodec.minimumInitialDatagramBytes {
        duplicatePayload.append(0x00)
        duplicateCryptoPacket.payload = duplicatePayload
        duplicateCryptoBytes = try duplicateCryptoPacket.encode()
    }
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(duplicateCryptoBytes)
    }

    let mismatchedServerInitial = try QUICLongHeaderPacket(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: Data([0x01, 0x02, 0x03, 0x04]),
        sourceConnectionID: decodedRequest.destinationConnectionID,
        packetNumber: 0,
        packetNumberLength: 2,
        payload: try QUICFrame.encodeFrames([
            .ack(largestAcknowledged: decodedRequest.packetNumber, ackDelay: 0, firstAckRange: 0, ranges: []),
            .crypto(offset: 0, data: Data("WT-QUIC-ACK\0hello".utf8))
        ])
    ).encode()
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeServerInitial(mismatchedServerInitial)
    }
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
