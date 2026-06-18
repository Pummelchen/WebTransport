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
