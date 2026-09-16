import Foundation
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple
@testable import WebTransportNetworkRuntime

extension WebTransportQUICPacketProbeCodec {
    static func makeClientHelloHandshakeMessage(message: String) throws -> TLSHandshakeMessage {
        try TLSClientHello(
            random: Data(repeating: 0x43, count: 32),
            legacySessionID: Data(message.utf8),
            extensions: [
                try TLSSupportedVersionsExtension.client(),
                try TLSALPNExtension.make(protocols: [h3ALPN]),
                try TLSQUICTransportParametersExtension.make(clientTransportParameters()),
                try TLSKeyShareExtension.client([
                    TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x11, count: 32))
                ]),
                try TLSSignatureAlgorithmsExtension.make([
                    TLSSignatureScheme.ed25519,
                    TLSSignatureScheme.ecdsaSecp256r1SHA256,
                ]),
            ]
        ).handshakeMessage()
    }

    // internal because the probe codec is declared across several files
    internal static func makeServerHelloHandshakeMessage(message: String) throws -> TLSHandshakeMessage {
        try TLSServerHello(
            random: Data(repeating: 0x53, count: 32),
            legacySessionIDEcho: Data(message.utf8),
            extensions: [
                TLSSupportedVersionsExtension.server(),
                try TLSKeyShareExtension.server(
                    TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x22, count: 32))
                ),
            ]
        ).handshakeMessage()
    }

    // internal because the probe codec is declared across several files
    internal static func makeEncryptedExtensionsHandshakeMessage(
        request: WebTransportQUICPacketProbeRequest
    ) throws -> TLSHandshakeMessage {
        try TLSEncryptedExtensions(extensions: [
            try TLSALPNExtension.make(protocols: [h3ALPN]),
            try TLSQUICTransportParametersExtension.make(serverTransportParameters(originalDestinationConnectionID: request.destinationConnectionID)),
        ]).handshakeMessage()
    }

    // internal because the probe codec is declared across several files
    internal static func makeServerHandshakeMessages(
        request: WebTransportQUICPacketProbeRequest,
        message: String
    ) throws -> [TLSHandshakeMessage] {
        var transcript = TLS13Transcript()
        for clientMessage in request.handshakeMessages {
            try transcript.append(clientMessage)
        }

        let serverHello = try makeServerHelloHandshakeMessage(message: message)
        try transcript.append(serverHello)

        let encryptedExtensions = try makeEncryptedExtensionsHandshakeMessage(request: request)
        try transcript.append(encryptedExtensions)

        let certificate = try TLSCertificate(entries: [
            try TLSCertificateEntry(certificateData: deterministicServerCertificateDER)
        ]).handshakeMessage()
        try transcript.append(certificate)

        let certificateVerify = try makeCertificateVerifyHandshakeMessage(transcriptHash: transcript.hash)
        try transcript.append(certificateVerify)

        let finished = try makeFinishedHandshakeMessage(transcriptHash: transcript.hash)
        return [serverHello, encryptedExtensions, certificate, certificateVerify, finished]
    }

    // internal because the probe codec is declared across several files
    internal static func makeCertificateVerifyHandshakeMessage(transcriptHash: Data) throws -> TLSHandshakeMessage {
        try TLSCertificateVerify(
            algorithm: TLSSignatureScheme.ed25519,
            signature: deterministicCertificateVerifySignature(transcriptHash: transcriptHash)
        ).handshakeMessage()
    }

    // internal because the probe codec is declared across several files
    internal static func makeFinishedHandshakeMessage(transcriptHash: Data) throws -> TLSHandshakeMessage {
        TLSFinished(
            verifyData: try TLS13KeySchedule.finishedVerifyData(
                baseKey: deterministicServerHandshakeTrafficSecret(),
                transcriptHash: transcriptHash
            )
        ).handshakeMessage()
    }

    // internal because the probe codec is declared across several files
    internal static func clientTransportParameters() throws -> QUICTransportParameters {
        var parameters = QUICTransportParameters()
        try parameters.setInteger(UInt64(minimumInitialDatagramBytes), for: QUICTransportParameterID.maxDatagramFrameSize)
        try parameters.setInteger(UInt64(minimumInitialDatagramBytes), for: QUICTransportParameterID.maxUDPPayloadSize)
        try parameters.setInteger(65_536, for: QUICTransportParameterID.initialMaxData)
        parameters[QUICTransportParameterID.initialSourceConnectionID] = clientSourceConnectionID
        return parameters
    }

    // internal because the probe codec is declared across several files
    internal static func serverTransportParameters(originalDestinationConnectionID: Data) throws -> QUICTransportParameters {
        var parameters = QUICTransportParameters()
        try parameters.setInteger(UInt64(minimumInitialDatagramBytes), for: QUICTransportParameterID.maxDatagramFrameSize)
        try parameters.setInteger(UInt64(minimumInitialDatagramBytes), for: QUICTransportParameterID.maxUDPPayloadSize)
        try parameters.setInteger(65_536, for: QUICTransportParameterID.initialMaxData)
        parameters[QUICTransportParameterID.originalDestinationConnectionID] = originalDestinationConnectionID
        parameters[QUICTransportParameterID.initialSourceConnectionID] = clientDestinationConnectionID
        return parameters
    }

    // internal because the probe codec is declared across several files
    internal static func decodeHandshakeFlight(
        from frames: [QUICFrame],
        expectedTypes: [TLSHandshakeType],
        requiresPing: Bool,
        requiresAck: Bool,
        peerHandshakeMessages: [TLSHandshakeMessage] = []
    ) throws -> (message: String, messages: [TLSHandshakeMessage]) {
        var hasPing = false
        var hasAck = false
        var cryptoFrames: [QUICFrame] = []

        for frame in frames {
            switch frame {
            case .padding:
                continue
            case .ping:
                hasPing = true
            case .ack:
                hasAck = true
            case .crypto:
                cryptoFrames.append(frame)
            default:
                throw WebTransportNetworkRuntimeError.unexpectedFrame
            }
        }

        guard !requiresPing || hasPing,
            !requiresAck || hasAck
        else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }

        var decoder = TLSHandshakeFlightDecoder()
        let messages = try decoder.receive(frames: cryptoFrames)
        guard messages.map(\.type) == expectedTypes,
            let first = messages.first
        else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }

        switch first.type {
        case .clientHello:
            let hello = try TLSClientHello.decode(first.body)
            try validateClientHello(hello)
            guard let message = String(data: hello.legacySessionID, encoding: .utf8) else {
                throw WebTransportNetworkRuntimeError.invalidPayload
            }
            return (message, messages)
        case .serverHello:
            let hello = try TLSServerHello.decode(first.body)
            try validateServerHello(hello)
            guard messages.count == 5,
                messages[1].type == .encryptedExtensions,
                messages[2].type == .certificate,
                messages[3].type == .certificateVerify,
                messages[4].type == .finished
            else {
                throw WebTransportNetworkRuntimeError.invalidPayload
            }
            let encryptedExtensions = try TLSEncryptedExtensions.decode(messages[1].body)
            try validateEncryptedExtensions(encryptedExtensions)
            try validateServerAuthentication(messages, peerHandshakeMessages: peerHandshakeMessages)
            guard let message = String(data: hello.legacySessionIDEcho, encoding: .utf8) else {
                throw WebTransportNetworkRuntimeError.invalidPayload
            }
            return (message, messages)
        default:
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
    }

    // internal because the probe codec is declared across several files
    internal static func validateClientHello(_ hello: TLSClientHello) throws {
        try validateALPN(hello.extensions)
        try validateTransportParameters(hello.extensions, requiresOriginalDestinationConnectionID: false)
        let supportedVersions = try requireExtension(.supportedVersions, in: hello.extensions)
        guard try TLSSupportedVersionsExtension.clientVersions(from: supportedVersions.data).contains(TLSProtocolVersion.tls13) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let keyShare = try requireExtension(.keyShare, in: hello.extensions)
        guard
            try TLSKeyShareExtension.clientShares(from: keyShare.data).contains(where: {
                $0.group == TLSNamedGroup.x25519 && $0.keyExchange.count == 32
            })
        else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
    }

    // internal because the probe codec is declared across several files
    internal static func validateServerHello(_ hello: TLSServerHello) throws {
        let supportedVersions = try requireExtension(.supportedVersions, in: hello.extensions)
        guard try TLSSupportedVersionsExtension.serverVersion(from: supportedVersions.data) == TLSProtocolVersion.tls13 else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let keyShare = try requireExtension(.keyShare, in: hello.extensions)
        let share = try TLSKeyShareExtension.serverShare(from: keyShare.data)
        guard share.group == TLSNamedGroup.x25519, share.keyExchange.count == 32 else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
    }

    // internal because the probe codec is declared across several files
    internal static func validateEncryptedExtensions(_ encryptedExtensions: TLSEncryptedExtensions) throws {
        try validateALPN(encryptedExtensions.extensions)
        try validateTransportParameters(
            encryptedExtensions.extensions,
            requiresOriginalDestinationConnectionID: true
        )
    }

    // internal because the probe codec is declared across several files
    internal static func validateServerAuthentication(
        _ messages: [TLSHandshakeMessage],
        peerHandshakeMessages: [TLSHandshakeMessage]
    ) throws {
        let certificate = try TLSCertificate.decode(messages[2].body)
        guard certificate.requestContext.isEmpty,
            certificate.entries.count == 1,
            certificate.entries[0].certificateData == deterministicServerCertificateDER
        else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }

        var transcript = TLS13Transcript()
        for message in peerHandshakeMessages {
            try transcript.append(message)
        }
        for message in messages.prefix(3) {
            try transcript.append(message)
        }
        let certificateVerify = try TLSCertificateVerify.decode(messages[3].body)
        guard certificateVerify.algorithm == TLSSignatureScheme.ed25519,
            certificateVerify.signature == deterministicCertificateVerifySignature(transcriptHash: transcript.hash)
        else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }

        try transcript.append(messages[3])
        let finished = TLSFinished.decode(messages[4].body)
        let expectedVerifyData = try TLS13KeySchedule.finishedVerifyData(
            baseKey: deterministicServerHandshakeTrafficSecret(),
            transcriptHash: transcript.hash
        )
        guard finished.verifyData == expectedVerifyData else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
    }

    // internal because the probe codec is declared across several files
    internal static func validateALPN(_ extensions: [TLSExtension]) throws {
        let alpn = try requireExtension(.applicationLayerProtocolNegotiation, in: extensions)
        guard try TLSALPNExtension.protocols(from: alpn.data) == [h3ALPN] else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
    }

    // internal because the probe codec is declared across several files
    internal static func validateTransportParameters(
        _ extensions: [TLSExtension],
        requiresOriginalDestinationConnectionID: Bool
    ) throws {
        let transportParametersExtension = try requireExtension(.quicTransportParameters, in: extensions)
        let parameters = try TLSQUICTransportParametersExtension.parameters(from: transportParametersExtension.data)
        guard try parameters.integer(for: QUICTransportParameterID.maxDatagramFrameSize) == UInt64(minimumInitialDatagramBytes),
            try parameters.integer(for: QUICTransportParameterID.maxUDPPayloadSize) == UInt64(minimumInitialDatagramBytes),
            parameters[QUICTransportParameterID.initialSourceConnectionID] != nil
        else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        if requiresOriginalDestinationConnectionID,
            parameters[QUICTransportParameterID.originalDestinationConnectionID] == nil
        {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
    }

    // internal because the probe codec is declared across several files
    internal static func requireExtension(
        _ type: TLSExtensionType,
        in extensions: [TLSExtension]
    ) throws -> TLSExtension {
        guard let item = extensions.first(where: { $0.type == type.rawValue }) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return item
    }
}
