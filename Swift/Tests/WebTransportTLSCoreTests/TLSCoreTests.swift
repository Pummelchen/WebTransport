import CryptoKit
import Foundation
import Testing
import WebTransportQUICCore
@testable import WebTransportTLSCore

@Test
func handshakeMessageEncodesUint24LengthAndTranscriptHash() throws {
    let message = TLSHandshakeMessage(type: .clientHello, body: Data([0x01, 0x02, 0x03]))
    let encoded = try message.encode()
    #expect(encoded == Data([0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]))
    #expect(try TLSHandshakeMessage.decodeAll(encoded) == [message])

    var transcript = TLS13Transcript()
    try transcript.append(message)
    #expect(transcript.hash == Data(SHA256.hash(data: encoded)))
}

@Test
func alpnExtensionEncodesAndDecodesH3() throws {
    let alpn = try TLSALPNExtension.make(protocols: ["h3"])
    #expect(alpn.type == TLSExtensionType.applicationLayerProtocolNegotiation.rawValue)
    #expect(try alpn.encode() == Data([0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33]))
    #expect(try TLSALPNExtension.protocols(from: alpn.data) == ["h3"])
}

@Test
func quicTransportParametersExtensionRoundTripsMaxDatagramSize() throws {
    var parameters = QUICTransportParameters()
    try parameters.setInteger(1_200, for: QUICTransportParameterID.maxDatagramFrameSize)

    let ext = try TLSQUICTransportParametersExtension.make(parameters)
    #expect(ext.type == TLSExtensionType.quicTransportParameters.rawValue)

    let decoded = try TLSQUICTransportParametersExtension.parameters(from: ext.data)
    #expect(try decoded.integer(for: QUICTransportParameterID.maxDatagramFrameSize) == 1_200)
}

@Test
func extensionListRoundTripsALPNAndQUICTransportParameters() throws {
    var parameters = QUICTransportParameters()
    try parameters.setInteger(65_535, for: QUICTransportParameterID.maxUDPPayloadSize)

    let extensions = [
        try TLSALPNExtension.make(protocols: ["h3"]),
        try TLSQUICTransportParametersExtension.make(parameters)
    ]

    let decoded = try TLSExtension.decodeList(try TLSExtension.encodeList(extensions))
    #expect(decoded == extensions)
}

@Test
func keyScheduleDerivesFinishedVerifyDataAndTrafficKeys() throws {
    let secret = try Data(hex: "1111111111111111111111111111111111111111111111111111111111111111")
    let transcriptHash = Data(SHA256.hash(data: Data("client-server-transcript".utf8)))

    let derived = try TLS13KeySchedule.deriveSecret(
        secret: secret,
        label: "c hs traffic",
        transcriptHash: transcriptHash
    )
    let finishedKey = try TLS13KeySchedule.finishedKey(baseKey: derived)
    let verifyData = try TLS13KeySchedule.finishedVerifyData(baseKey: derived, transcriptHash: transcriptHash)
    let trafficKeys = try TLS13KeySchedule.trafficKeys(trafficSecret: derived)

    #expect(derived.count == 32)
    #expect(finishedKey.count == 32)
    #expect(verifyData.count == 32)
    #expect(trafficKeys.key.count == 16)
    #expect(trafficKeys.iv.count == 12)
    #expect(verifyData != transcriptHash)
}

@Test
func typedTLS13HandshakeBodiesRoundTripWithQUICExtensions() throws {
    var parameters = QUICTransportParameters()
    try parameters.setInteger(1_200, for: QUICTransportParameterID.maxDatagramFrameSize)

    let clientHello = try TLSClientHello(
        random: Data(repeating: 0x01, count: 32),
        legacySessionID: Data([0xaa]),
        extensions: [
            try TLSSupportedVersionsExtension.client(),
            try TLSALPNExtension.make(protocols: ["h3"]),
            try TLSQUICTransportParametersExtension.make(parameters),
            try TLSKeyShareExtension.client([
                TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x11, count: 32))
            ]),
            try TLSSignatureAlgorithmsExtension.make([
                TLSSignatureScheme.ed25519,
                TLSSignatureScheme.ecdsaSecp256r1SHA256
            ])
        ]
    )
    let decodedClientHello = try TLSClientHello.decode(try clientHello.body())
    #expect(decodedClientHello == clientHello)

    let alpnExtension = try #require(decodedClientHello.extensions.first {
        $0.type == TLSExtensionType.applicationLayerProtocolNegotiation.rawValue
    })
    #expect(try TLSALPNExtension.protocols(from: alpnExtension.data) == ["h3"])

    let serverHello = try TLSServerHello(
        random: Data(repeating: 0x02, count: 32),
        legacySessionIDEcho: Data([0xaa]),
        extensions: [
            TLSSupportedVersionsExtension.server(),
            try TLSKeyShareExtension.server(
                TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x22, count: 32))
            )
        ]
    )
    #expect(try TLSServerHello.decode(try serverHello.body()) == serverHello)

    let encryptedExtensions = TLSEncryptedExtensions(extensions: [
        try TLSALPNExtension.make(protocols: ["h3"]),
        try TLSQUICTransportParametersExtension.make(parameters)
    ])
    #expect(try TLSEncryptedExtensions.decode(try encryptedExtensions.body()) == encryptedExtensions)
}

@Test
func typedHandshakeTranscriptProducesFinishedMessage() throws {
    let clientHello = try TLSClientHello(
        random: Data(repeating: 0x03, count: 32),
        extensions: [
            try TLSSupportedVersionsExtension.client(),
            try TLSALPNExtension.make(protocols: ["h3"])
        ]
    )
    let serverHello = try TLSServerHello(
        random: Data(repeating: 0x04, count: 32),
        extensions: [
            TLSSupportedVersionsExtension.server()
        ]
    )
    let encryptedExtensions = TLSEncryptedExtensions(extensions: [
        try TLSALPNExtension.make(protocols: ["h3"])
    ])

    var transcript = TLS13Transcript()
    try transcript.append(clientHello.handshakeMessage())
    try transcript.append(serverHello.handshakeMessage())
    try transcript.append(encryptedExtensions.handshakeMessage())

    let trafficSecret = try TLS13KeySchedule.deriveSecret(
        secret: Data(repeating: 0x55, count: 32),
        label: "s hs traffic",
        transcriptHash: transcript.hash
    )
    let verifyData = try TLS13KeySchedule.finishedVerifyData(
        baseKey: trafficSecret,
        transcriptHash: transcript.hash
    )
    let finished = TLSFinished(verifyData: verifyData)
    #expect(TLSFinished.decode(finished.handshakeMessage().body) == finished)
}

@Test
func typedExtensionDecodersRejectMalformedVectors() throws {
    try expectThrowing {
        _ = try TLSSupportedVersionsExtension.clientVersions(from: Data([0x00]))
    }
    try expectThrowing {
        _ = try TLSSupportedVersionsExtension.clientVersions(from: Data([0x03, 0x03, 0x04, 0x03]))
    }
    try expectThrowing {
        _ = try TLSSignatureAlgorithmsExtension.schemes(from: Data([0x00, 0x00]))
    }
    try expectThrowing {
        _ = try TLSSignatureAlgorithmsExtension.schemes(from: Data([0x00, 0x03, 0x04, 0x03, 0x08]))
    }
    try expectThrowing {
        _ = try TLSKeyShareExtension.serverShare(from: Data([0x00, 0x1d, 0x00, 0x00]))
    }
    try expectThrowing {
        _ = try TLSKeyShareExtension.clientShares(from: Data([0x00, 0x05, 0x00, 0x1d, 0x00, 0x20, 0x11]))
    }
}

private func expectThrowing(_ operation: () throws -> Void) throws {
    do {
        try operation()
    } catch {
        return
    }
    throw ExpectedThrowError.missingThrow
}

private enum ExpectedThrowError: Error {
    case missingThrow
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else {
            throw HexError.invalidLength
        }

        var output = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw HexError.invalidByte
            }
            output.append(byte)
            index = next
        }
        self = output
    }
}

private enum HexError: Error {
    case invalidLength
    case invalidByte
}
