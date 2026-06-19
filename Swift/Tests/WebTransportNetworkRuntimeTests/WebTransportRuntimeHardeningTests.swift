import Foundation
import Testing
@testable import WebTransportNetworkRuntime
import WebTransportQUICCore
import WebTransportTLSCore

@Test
func networkRuntimeRejectsImpairedPacketsAndTimeoutsDeterministically() throws {
    let client = WebTransportQUICPacketProbeClient()
    #expect(throws: Error.self) {
        _ = try client.run(
            to: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 9),
            message: "timeout-probe",
            timeoutMilliseconds: 50
        )
    }

    let clientInitial = try WebTransportQUICPacketProbeCodec.encodeClientInitial(message: "impaired")
    for count in stride(from: 0, to: clientInitial.count, by: max(1, clientInitial.count / 16)) {
        #expect(throws: Error.self) {
            _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(Data(clientInitial.prefix(count)))
        }
    }

    var duplicated = clientInitial
    duplicated.append(clientInitial)
    #expect(try WebTransportQUICPacketProbeCodec.decodeClientInitial(duplicated).message == "impaired")

    var tampered = clientInitial
    tampered[tampered.count / 2] ^= 0x55
    #expect(throws: Error.self) {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(tampered)
    }
}

@Test
func runtimeSecurityNegativesDoNotExposeSensitiveHandshakeMaterial() throws {
    let wrongALPNPacket = try protectedClientInitialForRuntimeHardening(
        message: "secret-message",
        alpn: "h2",
        maxDatagramFrameSize: 1_200
    )
    do {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(wrongALPNPacket)
        Issue.record("wrong ALPN packet unexpectedly decoded")
    } catch {
        let text = String(describing: error)
        #expect(!text.contains("secret-message"))
        #expect(!text.contains("certificate"))
        #expect(!text.contains("Finished"))
        #expect(!text.contains("key"))
    }

    let wrongTransportParameterPacket = try protectedClientInitialForRuntimeHardening(
        message: "secret-message",
        alpn: "h3",
        maxDatagramFrameSize: 1_199
    )
    do {
        _ = try WebTransportQUICPacketProbeCodec.decodeClientInitial(wrongTransportParameterPacket)
        Issue.record("wrong transport-parameter packet unexpectedly decoded")
    } catch {
        let text = String(describing: error)
        #expect(!text.contains("secret-message"))
        #expect(!text.contains("certificate"))
        #expect(!text.contains("Finished"))
        #expect(!text.contains("key"))
    }
}

@Test
func localSelfSignedTrustPolicyIsLoopbackOnly() async throws {
    let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
    await #expect(throws: WebTransportNetworkRuntimeError.self) {
        _ = try await client.run(
            to: WebTransportNetworkEndpoint(host: "example.com", port: 443),
            message: "must-not-connect",
            timeoutMilliseconds: 5_000
        )
    }
}

private func protectedClientInitialForRuntimeHardening(
    message: String,
    alpn: String,
    maxDatagramFrameSize: UInt64
) throws -> Data {
    var parameters = QUICTransportParameters()
    try parameters.setInteger(maxDatagramFrameSize, for: QUICTransportParameterID.maxDatagramFrameSize)
    try parameters.setInteger(1_200, for: QUICTransportParameterID.maxUDPPayloadSize)
    parameters[QUICTransportParameterID.initialSourceConnectionID] = Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e])

    let hello = try TLSClientHello(
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
    var payload = try QUICFrame.encodeFrames(
        try TLSHandshakeFlight(messages: [hello]).cryptoFrames(maxFramePayloadBytes: 8) + [.ping]
    )
    var encoded = try QUICInitialPacketProtection.seal(
        packetType: .initial,
        version: WebTransportQUICPacketProbeCodec.quicVersion,
        destinationConnectionID: Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65]),
        sourceConnectionID: Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e]),
        token: Data(),
        packetNumber: 0,
        packetNumberLength: 2,
        plaintextPayload: payload,
        keyPhase: .client,
        initialSecretConnectionID: Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65])
    )
    while encoded.count < WebTransportQUICPacketProbeCodec.minimumInitialDatagramBytes {
        payload.append(0x00)
        encoded = try QUICInitialPacketProtection.seal(
            packetType: .initial,
            version: WebTransportQUICPacketProbeCodec.quicVersion,
            destinationConnectionID: Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65]),
            sourceConnectionID: Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e]),
            token: Data(),
            packetNumber: 0,
            packetNumberLength: 2,
            plaintextPayload: payload,
            keyPhase: .client,
            initialSecretConnectionID: Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65])
        )
    }
    return encoded
}
