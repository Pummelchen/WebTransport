import Foundation
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple
@testable import WebTransportNetworkRuntime

enum WebTransportQUICPacketProbeCodec {
    static let quicVersion: UInt32 = 0x0000_0001
    static let minimumInitialDatagramBytes = 1_200

    // internal because the probe codec is declared across several files
    internal static let clientDestinationConnectionID = Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65])
    // internal because the probe codec is declared across several files
    internal static let clientSourceConnectionID = Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e])
    // internal because the probe codec is declared across several files
    internal static let h3ALPN = "h3"
    private static let sessionAuthority = "localhost"
    private static let sessionPath = "/wt"
    private static let sessionOrigin = "https://localhost"
    private static let sessionProtocol = "demo.v1"
    private static let sessionStreamID: UInt64 = 0
    private static let applicationPacketNumber: UInt64 = 1
    // internal because the probe codec is declared across several files
    internal static let deterministicServerCertificateDER = Data([0x30, 0x03, 0x02, 0x01, 0x05])
    private static let deterministicSharedSecret = Data(repeating: 0x5a, count: TLS13KeySchedule.sha256Length)
    private static let clientCryptoFramePayloadBytes = 7
    private static let serverCryptoFramePayloadBytes = 9

    static func encodeClientInitial(
        message: String,
        packetNumber: UInt64 = 0
    ) throws -> Data {
        let flight = TLSHandshakeFlight(messages: [
            try makeClientHelloHandshakeMessage(message: message)
        ])
        return try encodeProtectedInitial(
            InitialPacketEncoding(
                destinationConnectionID: clientDestinationConnectionID,
                sourceConnectionID: clientSourceConnectionID,
                packetNumber: packetNumber,
                keyPhase: .client,
                initialSecretConnectionID: clientDestinationConnectionID,
                frames: try flight.cryptoFrames(maxFramePayloadBytes: clientCryptoFramePayloadBytes) + [.ping],
                minimumDatagramBytes: minimumInitialDatagramBytes
            )
        )
    }

    static func encodeServerInitial(
        request: WebTransportQUICPacketProbeRequest,
        message: String,
        packetNumber: UInt64 = 0
    ) throws -> Data {
        try encodeServerInitial(
            handshakeContext: serverHandshakeContext(request: request, message: message),
            packetNumber: packetNumber
        )
    }

    static func encodeServerInitial(
        handshakeContext: WebTransportQUICPacketHandshakeContext,
        packetNumber: UInt64 = 0
    ) throws -> Data {
        let request = handshakeContext.request
        let flight = TLSHandshakeFlight(messages: handshakeContext.serverHandshakeMessages)
        return try encodeProtectedInitial(
            InitialPacketEncoding(
                destinationConnectionID: request.sourceConnectionID,
                sourceConnectionID: request.destinationConnectionID,
                packetNumber: packetNumber,
                keyPhase: .server,
                initialSecretConnectionID: request.destinationConnectionID,
                frames: [.ack(largestAcknowledged: request.packetNumber, ackDelay: 0, firstAckRange: 0, ranges: [])]
                    + (try flight.cryptoFrames(maxFramePayloadBytes: serverCryptoFramePayloadBytes)),
                minimumDatagramBytes: 0
            )
        )
    }

    static func decodeClientInitial(_ data: Data) throws -> WebTransportQUICPacketProbeRequest {
        guard data.count >= minimumInitialDatagramBytes else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let packet = try decodeProtectedInitial(data, keyPhase: .client)
        let frames = try QUICFrame.decodeFrames(packet.payload)
        let decoded = try decodeHandshakeFlight(
            from: frames,
            expectedTypes: [.clientHello],
            requiresPing: true,
            requiresAck: false
        )
        return WebTransportQUICPacketProbeRequest(
            message: decoded.message,
            packetNumber: packet.packetNumber,
            destinationConnectionID: packet.destinationConnectionID,
            sourceConnectionID: packet.sourceConnectionID,
            handshakeMessages: decoded.messages
        )
    }

    static func decodeServerInitial(
        _ data: Data,
        request: WebTransportQUICPacketProbeRequest
    ) throws -> String {
        try decodeServerInitialContext(data, request: request).message
    }

    static func decodeServerInitialContext(
        _ data: Data,
        request: WebTransportQUICPacketProbeRequest
    ) throws -> WebTransportQUICPacketHandshakeContext {
        let packet = try decodeProtectedInitial(
            data,
            keyPhase: .server,
            initialSecretConnectionID: clientDestinationConnectionID
        )
        guard packet.destinationConnectionID == clientSourceConnectionID,
            packet.sourceConnectionID == clientDestinationConnectionID
        else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let frames = try QUICFrame.decodeFrames(packet.payload)
        let decoded = try decodeHandshakeFlight(
            from: frames,
            expectedTypes: [.serverHello, .encryptedExtensions, .certificate, .certificateVerify, .finished],
            requiresPing: false,
            requiresAck: true,
            peerHandshakeMessages: request.handshakeMessages
        )
        return try applicationHandshakeContext(
            request: request,
            message: decoded.message,
            serverHandshakeMessages: decoded.messages
        )
    }

    static func serverHandshakeContext(
        request: WebTransportQUICPacketProbeRequest,
        message: String
    ) throws -> WebTransportQUICPacketHandshakeContext {
        try applicationHandshakeContext(
            request: request,
            message: message,
            serverHandshakeMessages: makeServerHandshakeMessages(request: request, message: message)
        )
    }

    static func encodeClientApplicationRequest(
        handshakeContext: WebTransportQUICPacketHandshakeContext,
        message: String
    ) throws -> Data {
        let request = handshakeContext.request
        let sessionRequest = try WebTransportSessionRequest(
            authority: sessionAuthority,
            path: sessionPath,
            origin: sessionOrigin,
            availableProtocols: [sessionProtocol]
        )
        let headersFrame = try QPACK.headersFrame(fields: sessionRequest.headers())
        let streamBytes = try HTTP3Frame.encodeFrames([headersFrame])
        let datagram = try WebTransportDatagramSignaling.serialize(
            sessionID: sessionStreamID,
            payload: Data(message.utf8)
        )
        return try encodeProtectedShortHeader(
            destinationConnectionID: request.destinationConnectionID,
            packetNumber: applicationPacketNumber,
            keyPhase: .client,
            keys: handshakeContext.clientApplicationKeys,
            frames: [
                .ack(largestAcknowledged: request.packetNumber, ackDelay: 0, firstAckRange: 0, ranges: []),
                .stream(id: sessionStreamID, offset: 0, fin: false, data: streamBytes),
                .datagram(datagram),
            ]
        )
    }

    static func decodeClientApplicationRequest(
        _ data: Data,
        handshakeContext: WebTransportQUICPacketHandshakeContext
    ) throws -> WebTransportQUICPacketApplicationRequest {
        let request = handshakeContext.request
        let packet = try decodeProtectedShortHeader(
            data,
            destinationConnectionID: request.destinationConnectionID,
            keyPhase: .client,
            keys: handshakeContext.clientApplicationKeys
        )
        guard packet.packetNumber == applicationPacketNumber else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let frames = try QUICFrame.decodeFrames(packet.payload)
        let fields = try requestHeaderFields(from: frames)
        try WebTransportHTTP3Headers.validateConnectRequest(fields)
        guard try availableProtocols(from: fields).contains(sessionProtocol) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let message = try messageDatagram(from: frames)
        return WebTransportQUICPacketApplicationRequest(
            message: message,
            packetNumber: packet.packetNumber,
            requestHeaders: fields
        )
    }

    static func encodeServerApplicationResponse(
        handshakeContext: WebTransportQUICPacketHandshakeContext,
        message: String
    ) throws -> Data {
        let request = handshakeContext.request
        var responseFields = try WebTransportHTTP3Headers.successfulResponse(status: 200)
        responseFields.append(
            try HTTPFieldLine(
                name: WebTransportHeaderName.selectedProtocol,
                value: WebTransportProtocolNegotiation.encodeItem(sessionProtocol)
            ))
        let headersFrame = try QPACK.headersFrame(fields: responseFields)
        let streamBytes = try HTTP3Frame.encodeFrames([headersFrame])
        let datagram = try WebTransportDatagramSignaling.serialize(
            sessionID: sessionStreamID,
            payload: Data(message.utf8)
        )
        return try encodeProtectedShortHeader(
            destinationConnectionID: request.sourceConnectionID,
            packetNumber: applicationPacketNumber,
            keyPhase: .server,
            keys: handshakeContext.serverApplicationKeys,
            frames: [
                .handshakeDone,
                .ack(largestAcknowledged: applicationPacketNumber, ackDelay: 0, firstAckRange: 0, ranges: []),
                .stream(id: sessionStreamID, offset: 0, fin: false, data: streamBytes),
                .datagram(datagram),
            ]
        )
    }

    static func decodeServerApplicationResponse(
        _ data: Data,
        handshakeContext: WebTransportQUICPacketHandshakeContext
    ) throws -> String {
        let request = handshakeContext.request
        let packet = try decodeProtectedShortHeader(
            data,
            destinationConnectionID: request.sourceConnectionID,
            keyPhase: .server,
            keys: handshakeContext.serverApplicationKeys
        )
        guard packet.packetNumber == applicationPacketNumber else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let frames = try QUICFrame.decodeFrames(packet.payload)
        let fields = try responseHeaderFields(from: frames)
        try WebTransportHTTP3Headers.validateSuccessfulResponse(fields)
        guard try selectedProtocol(from: fields) == sessionProtocol else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return try messageDatagram(from: frames)
    }

    /// Everything one protected Initial packet is built from, as a single value.
    private struct InitialPacketEncoding {
        var destinationConnectionID: Data
        var sourceConnectionID: Data
        var packetNumber: UInt64
        var keyPhase: QUICInitialPacketProtection.KeyPhase
        var initialSecretConnectionID: Data
        var frames: [QUICFrame]
        var minimumDatagramBytes: Int
    }

    private static func encodeProtectedInitial(
        _ encoding: InitialPacketEncoding
    ) throws -> Data {
        let destinationConnectionID = encoding.destinationConnectionID
        let sourceConnectionID = encoding.sourceConnectionID
        let packetNumber = encoding.packetNumber
        let keyPhase = encoding.keyPhase
        let initialSecretConnectionID = encoding.initialSecretConnectionID
        let frames = encoding.frames
        let minimumDatagramBytes = encoding.minimumDatagramBytes
        var payload = try QUICFrame.encodeFrames(frames)
        var encoded = try QUICInitialPacketProtection.seal(
            QUICInitialPacketProtection.SealRequest(
                packetType: .initial,
                version: quicVersion,
                destinationConnectionID: destinationConnectionID,
                sourceConnectionID: sourceConnectionID,
                token: Data(),
                packetNumber: packetNumber,
                packetNumberLength: 2,
                plaintextPayload: payload,
                keyPhase: keyPhase,
                initialSecretConnectionID: initialSecretConnectionID
            ))
        while encoded.count < minimumDatagramBytes {
            payload.append(0x00)
            encoded = try QUICInitialPacketProtection.seal(
                QUICInitialPacketProtection.SealRequest(
                    packetType: .initial,
                    version: quicVersion,
                    destinationConnectionID: destinationConnectionID,
                    sourceConnectionID: sourceConnectionID,
                    token: Data(),
                    packetNumber: packetNumber,
                    packetNumberLength: 2,
                    plaintextPayload: payload,
                    keyPhase: keyPhase,
                    initialSecretConnectionID: initialSecretConnectionID
                ))
        }
        return encoded
    }

    private static func encodeProtectedShortHeader(
        destinationConnectionID: Data,
        packetNumber: UInt64,
        keyPhase: QUICInitialPacketProtection.KeyPhase,
        keys: QUICPacketProtectionKeys,
        frames: [QUICFrame]
    ) throws -> Data {
        let plaintextPayload = try QUICFrame.encodeFrames(frames)
        let packetNumberLength = 2
        let packetNumberBytes = try QUICPacketNumber.encodeTruncated(packetNumber, byteCount: packetNumberLength)
        var header = Data()
        header.append(0x40 | UInt8(packetNumberLength - 1))
        header.append(destinationConnectionID)
        let packetNumberOffset = header.count
        header.append(packetNumberBytes)
        let ciphertextAndTag = try QUICPacketProtection.seal(
            plaintext: plaintextPayload,
            packetNumber: packetNumber,
            associatedData: header,
            keys: keys
        )
        return try QUICInitialPacketProtection.applyHeaderProtection(
            headerAndCiphertext: header + ciphertextAndTag,
            packetNumberOffset: packetNumberOffset,
            packetNumberLength: packetNumberLength,
            headerProtectionKey: keys.headerProtectionKey
        )
    }

    private static func decodeProtectedShortHeader(
        _ data: Data,
        destinationConnectionID: Data,
        keyPhase: QUICInitialPacketProtection.KeyPhase,
        keys: QUICPacketProtectionKeys
    ) throws -> QUICShortHeaderPacket {
        guard data.count >= 1 + destinationConnectionID.count + 2 + 16 else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        var unprotected = data
        let packetNumberOffset = 1 + destinationConnectionID.count
        try QUICInitialPacketProtection.removeHeaderProtection(
            packet: &unprotected,
            packetNumberOffset: packetNumberOffset,
            headerProtectionKey: keys.headerProtectionKey
        )
        let first = unprotected[0]
        guard (first & 0x80) == 0, (first & 0x40) != 0 else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let packetNumberLength = Int(first & 0x03) + 1
        guard packetNumberOffset + packetNumberLength <= unprotected.count else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        guard Data(unprotected[1..<packetNumberOffset]) == destinationConnectionID else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let packetNumberBytes = unprotected[packetNumberOffset..<(packetNumberOffset + packetNumberLength)]
        let truncatedPacketNumber = packetNumberBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let packetNumber = try QUICPacketNumber.decodeTruncated(
            truncatedPacketNumber,
            byteCount: packetNumberLength,
            largestAcknowledged: nil
        )
        let associatedData = Data(unprotected[..<(packetNumberOffset + packetNumberLength)])
        let ciphertextAndTag = Data(unprotected[(packetNumberOffset + packetNumberLength)...])
        let plaintextPayload = try QUICPacketProtection.open(
            ciphertextAndTag: ciphertextAndTag,
            packetNumber: packetNumber,
            associatedData: associatedData,
            keys: keys
        )
        return QUICShortHeaderPacket(
            destinationConnectionID: destinationConnectionID,
            keyPhase: (first & 0x04) != 0,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: plaintextPayload
        )
    }

    private static func decodeProtectedInitial(
        _ data: Data,
        keyPhase: QUICInitialPacketProtection.KeyPhase,
        initialSecretConnectionID explicitInitialSecretConnectionID: Data? = nil
    ) throws -> QUICLongHeaderPacket {
        let parsed = try QUICInitialPacketProtection.parseProtectedLongHeader(data)
        let packet = try QUICInitialPacketProtection.open(
            data,
            keyPhase: keyPhase,
            initialSecretConnectionID: explicitInitialSecretConnectionID ?? parsed.destinationConnectionID,
            parsedHeader: parsed
        )
        guard packet.packetType == .initial,
            packet.version == quicVersion,
            packet.token.isEmpty
        else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        return packet
    }

    private static func requestHeaderFields(from frames: [QUICFrame]) throws -> [HTTPFieldLine] {
        try headerFields(from: frames)
    }

    private static func responseHeaderFields(from frames: [QUICFrame]) throws -> [HTTPFieldLine] {
        let fields = try headerFields(from: frames)
        guard fields.contains(where: { $0.name == ":status" }) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return fields
    }

    private static func headerFields(from frames: [QUICFrame]) throws -> [HTTPFieldLine] {
        let streamData = try streamData(from: frames)
        let httpFrames = try HTTP3Frame.decodeFrames(streamData)
        guard let headers = httpFrames.first(where: { $0.type == HTTP3FrameType.headers }) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return try QPACK.decodeHeadersFrame(headers)
    }

    private static func streamData(from frames: [QUICFrame]) throws -> Data {
        let streams = frames.compactMap { frame -> Data? in
            guard case .stream(let id, _, _, let data) = frame, id == sessionStreamID else {
                return nil
            }
            return data
        }
        guard streams.count == 1, let data = streams.first else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return data
    }

    private static func messageDatagram(from frames: [QUICFrame]) throws -> String {
        let datagrams = frames.compactMap { frame -> Data? in
            guard case .datagram(let payload) = frame else {
                return nil
            }
            return payload
        }
        guard datagrams.count == 1, let datagram = datagrams.first else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let parsed = try WebTransportDatagramSignaling.parse(datagram)
        guard parsed.sessionID.rawValue == sessionStreamID,
            let message = String(data: parsed.payload, encoding: .utf8)
        else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return message
    }

    private static func availableProtocols(from fields: [HTTPFieldLine]) throws -> [String] {
        guard let field = fields.first(where: { $0.name == WebTransportHeaderName.availableProtocols }) else {
            return []
        }
        return try WebTransportProtocolNegotiation.decodeList(field.value)
    }

    private static func selectedProtocol(from fields: [HTTPFieldLine]) throws -> String? {
        guard let field = fields.first(where: { $0.name == WebTransportHeaderName.selectedProtocol }) else {
            return nil
        }
        return try WebTransportProtocolNegotiation.decodeItem(field.value)
    }

    // internal because the probe codec is declared across several files
    internal static func applicationHandshakeContext(
        request: WebTransportQUICPacketProbeRequest,
        message: String,
        serverHandshakeMessages: [TLSHandshakeMessage]
    ) throws -> WebTransportQUICPacketHandshakeContext {
        var state = TLSQUICConnectionState(role: .client)
        let transcriptMessages = request.handshakeMessages + serverHandshakeMessages
        _ = try state.receiveHandshakeFrames(TLSHandshakeFlight(messages: transcriptMessages).cryptoFrames(maxFramePayloadBytes: 16))
        _ = try state.deriveHandshakeTrafficSecrets(sharedSecret: deterministicSharedSecret)
        state.markApplicationKeyRequirementsSatisfied(TLSQUICApplicationKeyRequirement.allCases)
        let trafficSecrets = try state.deriveApplicationTrafficSecrets()
        return WebTransportQUICPacketHandshakeContext(
            request: request,
            message: message,
            serverHandshakeMessages: serverHandshakeMessages,
            clientApplicationKeys: try QUICPacketProtection.deriveKeys(
                trafficSecret: trafficSecrets.clientApplicationTrafficSecret
            ),
            serverApplicationKeys: try QUICPacketProtection.deriveKeys(
                trafficSecret: trafficSecrets.serverApplicationTrafficSecret
            )
        )
    }

    // internal because the probe codec is declared across several files
    internal static func deterministicCertificateVerifySignature(transcriptHash: Data) -> Data {
        let signedContent = TLSCertificateVerifier.signedContent(role: .server, transcriptHash: transcriptHash)
        let first = TLS13KeySchedule.transcriptHash(signedContent)
        let second = TLS13KeySchedule.transcriptHash(Data(signedContent.reversed()))
        return first + second
    }

    // internal because the probe codec is declared across several files
    internal static func deterministicServerHandshakeTrafficSecret() throws -> Data {
        let handshakeSecret = try TLS13KeyAgreement.handshakeSecret(sharedSecret: deterministicSharedSecret)
        return try TLS13KeyAgreement.handshakeTrafficSecrets(
            handshakeSecret: handshakeSecret,
            transcriptHash: TLS13KeySchedule.transcriptHash(Data("WebTransportNetworkRuntime server handshake".utf8))
        ).serverHandshakeTrafficSecret
    }
}
