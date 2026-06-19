import CryptoKit
import Foundation
import Security
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
func extensionListRejectsDuplicateExtensionTypes() throws {
    let duplicateList = try TLSExtension.encodeList([
        try TLSALPNExtension.make(protocols: ["h3"]),
        try TLSALPNExtension.make(protocols: ["h3-29"])
    ])

    #expect(throws: Error.self) {
        _ = try TLSExtension.decodeList(duplicateList)
    }
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
func x25519KeyAgreementDerivesHandshakeTrafficSecrets() throws {
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
    #expect(clientSharedSecret == serverSharedSecret)
    #expect(clientSharedSecret != TLS13KeyAgreement.zeroSecret)

    let clientHello = try TLSClientHello(
        random: Data(repeating: 0x05, count: 32),
        extensions: [
            try TLSSupportedVersionsExtension.client(),
            try TLSKeyShareExtension.client([clientShare]),
            try TLSALPNExtension.make(protocols: ["h3"])
        ]
    )
    let serverHello = try TLSServerHello(
        random: Data(repeating: 0x06, count: 32),
        extensions: [
            TLSSupportedVersionsExtension.server(),
            try TLSKeyShareExtension.server(serverShare)
        ]
    )

    var transcript = TLS13Transcript()
    try transcript.append(clientHello.handshakeMessage())
    try transcript.append(serverHello.handshakeMessage())

    let handshakeSecret = try TLS13KeyAgreement.handshakeSecret(sharedSecret: clientSharedSecret)
    let trafficSecrets = try TLS13KeyAgreement.handshakeTrafficSecrets(
        handshakeSecret: handshakeSecret,
        transcriptHash: transcript.hash
    )
    let clientKeys = try TLS13KeySchedule.trafficKeys(trafficSecret: trafficSecrets.clientHandshakeTrafficSecret)
    let serverKeys = try TLS13KeySchedule.trafficKeys(trafficSecret: trafficSecrets.serverHandshakeTrafficSecret)

    #expect(handshakeSecret.count == TLS13KeySchedule.sha256Length)
    #expect(trafficSecrets.clientHandshakeTrafficSecret != trafficSecrets.serverHandshakeTrafficSecret)
    #expect(clientKeys.key.count == 16 && clientKeys.iv.count == 12)
    #expect(serverKeys.key.count == 16 && serverKeys.iv.count == 12)
}

@Test
func tls13NoPSKHandshakeSecretUsesExtractedEarlySecret() throws {
    let sharedSecret = Data(repeating: 0x42, count: TLS13KeySchedule.sha256Length)
    let derived = try TLS13KeySchedule.deriveSecret(
        secret: TLS13KeyAgreement.noPSKEarlySecret,
        label: "derived",
        transcriptHash: TLS13KeySchedule.transcriptHash(Data())
    )
    let expected = TLS13KeySchedule.hkdfExtract(inputKeyMaterial: sharedSecret, salt: derived)

    #expect(TLS13KeyAgreement.noPSKEarlySecret != TLS13KeyAgreement.zeroSecret)
    #expect(try TLS13KeyAgreement.handshakeSecret(sharedSecret: sharedSecret) == expected)
}

@Test
func tls13ApplicationTrafficSecretsDeriveFromMasterSecret() throws {
    let handshakeSecret = Data(repeating: 0x77, count: TLS13KeySchedule.sha256Length)
    let masterSecret = try TLS13KeyAgreement.masterSecret(handshakeSecret: handshakeSecret)
    let transcriptHash = TLS13KeySchedule.transcriptHash(Data("complete-handshake-transcript".utf8))
    let applicationSecrets = try TLS13KeyAgreement.applicationTrafficSecrets(
        masterSecret: masterSecret,
        transcriptHash: transcriptHash
    )
    let nextClientSecret = try TLS13KeyAgreement.nextApplicationTrafficSecret(
        applicationSecrets.clientApplicationTrafficSecret
    )

    #expect(masterSecret.count == TLS13KeySchedule.sha256Length)
    #expect(applicationSecrets.clientApplicationTrafficSecret.count == TLS13KeySchedule.sha256Length)
    #expect(applicationSecrets.serverApplicationTrafficSecret.count == TLS13KeySchedule.sha256Length)
    #expect(applicationSecrets.clientApplicationTrafficSecret != applicationSecrets.serverApplicationTrafficSecret)
    #expect(nextClientSecret != applicationSecrets.clientApplicationTrafficSecret)
    #expect(nextClientSecret.count == TLS13KeySchedule.sha256Length)
}

@Test
func x25519KeyAgreementRejectsInvalidPeerShares() throws {
    let privateKey = TLS13KeyAgreement.makeX25519PrivateKey()

    try expectThrowing {
        _ = try TLS13KeyAgreement.x25519SharedSecret(
            privateKey: privateKey,
            peerShare: TLSKeyShareEntry(group: TLSNamedGroup.secp256r1, keyExchange: Data(repeating: 0x01, count: 32))
        )
    }
    try expectThrowing {
        _ = try TLS13KeyAgreement.x25519SharedSecret(
            privateKey: privateKey,
            peerShare: TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: Data(repeating: 0x01, count: 31))
        )
    }
}

@Test
func promptFreeServerIdentityImportsPrivateKeyWithoutKeychain() throws {
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: 2_048,
        kSecAttrIsPermanent: false
    ]
    var error: Unmanaged<CFError>?
    guard let generatedKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error?.takeRetainedValue() ?? ExpectedThrowError.missingThrow
    }
    guard let privateKeyDER = SecKeyCopyExternalRepresentation(generatedKey, &error) as Data? else {
        throw error?.takeRetainedValue() ?? ExpectedThrowError.missingThrow
    }

    let identity = try TLSPromptFreeServerIdentity(
        certificateChainDER: [Data([0x30, 0x00])],
        privateKeyDER: privateKeyDER,
        privateKeyType: kSecAttrKeyTypeRSA,
        privateKeySizeInBits: 2_048
    )
    let importedKey = try identity.makePrivateKey()

    #expect(SecKeyCopyPublicKey(importedKey) != nil)
}

@Test
func promptFreeIdentityAndTrustRejectInvalidInputs() throws {
    try expectThrowing {
        _ = try TLSPromptFreeServerIdentity(
            certificateChainDER: [],
            privateKeyDER: Data([0x01]),
            privateKeyType: kSecAttrKeyTypeRSA,
            privateKeySizeInBits: 2_048
        )
    }

    let identity = try TLSPromptFreeServerIdentity(
        certificateChainDER: [Data([0x00, 0x01, 0x02])],
        privateKeyDER: Data([0x00, 0x01, 0x02]),
        privateKeyType: kSecAttrKeyTypeRSA,
        privateKeySizeInBits: 2_048
    )
    try expectThrowing {
        _ = try identity.makeCertificateChain()
    }
    try expectThrowing {
        _ = try identity.makePrivateKey()
    }
    try expectThrowing {
        _ = try TLSPinnedCertificateTrustPolicy(allowedLeafCertificateSHA256Fingerprints: [])
    }
    try expectThrowing {
        _ = try TLSPinnedCertificateTrustPolicy(
            allowedLeafCertificateSHA256Fingerprints: [Data(repeating: 0x01, count: 31)]
        )
    }

    let policy = try TLSPinnedCertificateTrustPolicy(
        allowedLeafCertificateSHA256Fingerprints: [Data(repeating: 0x02, count: 32)]
    )
    try expectThrowing {
        try policy.evaluate(certificateChainDER: [])
    }
    try expectThrowing {
        try policy.evaluate(certificateChainDER: [Data([0x00, 0x01, 0x02])])
    }
}

@Test
func promptFreeTrustPolicyRejectsWrongPinForValidCertificate() throws {
    let certificateDER = try PromptFreeCertificateFixture.makeCertificateDER()
    #expect(SecCertificateCreateWithData(nil, certificateDER as CFData) != nil)

    let wrongPolicy = try TLSPinnedCertificateTrustPolicy(
        allowedLeafCertificateSHA256Fingerprints: [
            Data(repeating: 0x7a, count: TLS13KeySchedule.sha256Length)
        ]
    )
    do {
        try wrongPolicy.evaluate(certificateChainDER: [certificateDER])
        Issue.record("wrong certificate pin should be rejected")
    } catch let error as QUICCodecError {
        #expect(error == .malformed("peer leaf certificate fingerprint is not pinned"))
    }

    let correctPolicy = try TLSPinnedCertificateTrustPolicy(
        allowedLeafCertificateSHA256Fingerprints: [
            TLSPinnedCertificateTrustPolicy.sha256Fingerprint(certificateDER: certificateDER)
        ]
    )
    try correctPolicy.evaluate(certificateChainDER: [certificateDER])
}

@Test
func certificateHandshakeMessagesRoundTrip() throws {
    let entry = try TLSCertificateEntry(
        certificateData: Data([0x30, 0x03, 0x02, 0x01, 0x05]),
        extensions: [
            TLSExtension(type: 0xfe00, data: Data([0x01, 0x02]))
        ]
    )
    let certificate = try TLSCertificate(entries: [entry])
    #expect(try TLSCertificate.decode(try certificate.body()) == certificate)
    #expect(try certificate.handshakeMessage().type == .certificate)

    let certificateVerify = try TLSCertificateVerify(
        algorithm: TLSSignatureScheme.ed25519,
        signature: Data(repeating: 0xaa, count: 64)
    )
    #expect(try TLSCertificateVerify.decode(certificateVerify.body()) == certificateVerify)
    #expect(certificateVerify.handshakeMessage().type == .certificateVerify)
}

@Test
func certificateHandshakeMessagesRejectMalformedVectors() throws {
    try expectThrowing {
        _ = try TLSCertificateEntry(certificateData: Data())
    }
    try expectThrowing {
        _ = try TLSCertificate(entries: [])
    }
    try expectThrowing {
        _ = try TLSCertificateVerify(algorithm: TLSSignatureScheme.ed25519, signature: Data())
    }
    try expectThrowing {
        _ = try TLSCertificate.decode(Data([0x00, 0x00, 0x00, 0x01]))
    }
    try expectThrowing {
        _ = try TLSCertificateVerify.decode(Data([0x08, 0x07, 0x00, 0x02, 0xaa]))
    }
}

@Test
func certificateVerifySignatureVerifiesWithInMemorySecKey() throws {
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: 2_048,
        kSecAttrIsPermanent: false
    ]
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error?.takeRetainedValue() ?? ExpectedThrowError.missingThrow
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw ExpectedThrowError.missingThrow
    }

    let transcriptHash = TLS13KeySchedule.transcriptHash(Data("certificate-verify-transcript".utf8))
    let algorithm = try TLSCertificateVerifier.secKeyAlgorithm(for: TLSSignatureScheme.rsaPSSRSAESHA256)
    let signedContent = TLSCertificateVerifier.signedContent(role: .server, transcriptHash: transcriptHash)
    guard let signature = SecKeyCreateSignature(
        privateKey,
        algorithm,
        signedContent as CFData,
        &error
    ) as Data? else {
        throw error?.takeRetainedValue() ?? ExpectedThrowError.missingThrow
    }

    let certificateVerify = try TLSCertificateVerify(
        algorithm: TLSSignatureScheme.rsaPSSRSAESHA256,
        signature: signature
    )
    #expect(try TLSCertificateVerifier.verify(
        certificateVerify,
        role: .server,
        transcriptHash: transcriptHash,
        publicKey: publicKey
    ))
    #expect(try TLSCertificateVerifier.verify(
        certificateVerify,
        role: .server,
        transcriptHash: TLS13KeySchedule.transcriptHash(Data("tampered".utf8)),
        publicKey: publicKey
    ) == false)
    try expectThrowing {
        _ = try TLSCertificateVerifier.secKeyAlgorithm(for: TLSSignatureScheme.ed25519)
    }
}

@Test
func handshakeFlightFragmentsReassemblesAndUpdatesTranscript() throws {
    let messages = [
        TLSHandshakeMessage(type: .clientHello, body: Data(repeating: 0x01, count: 7)),
        TLSHandshakeMessage(type: .serverHello, body: Data(repeating: 0x02, count: 5)),
        TLSHandshakeMessage(type: .encryptedExtensions, body: Data([0x03, 0x04, 0x05]))
    ]
    let flight = TLSHandshakeFlight(messages: messages)
    let frames = try flight.cryptoFrames(maxFramePayloadBytes: 4)
    #expect(frames.count > messages.count)

    var decoder = TLSHandshakeFlightDecoder()
    #expect(try decoder.receive(frame: frames[2]).isEmpty)
    #expect(try decoder.receive(frame: frames[1]).isEmpty)
    let firstDecoded = try decoder.receive(frame: frames[0])
    #expect(firstDecoded == [messages[0]])

    let restDecoded = try decoder.receive(frames: Array(frames.dropFirst(3)))
    #expect(firstDecoded + restDecoded == messages)
    #expect(decoder.transcript.hash == TLS13KeySchedule.transcriptHash(try flight.encodedBytes()))
    #expect(decoder.consumedByteCount == UInt64(try flight.encodedBytes().count))
}

@Test
func handshakeFlightBuffersPartialMessagesUntilComplete() throws {
    let message = TLSHandshakeMessage(type: .finished, body: Data(repeating: 0xaa, count: 12))
    let frames = try TLSHandshakeFlight(messages: [message]).cryptoFrames(maxFramePayloadBytes: 5)
    var decoder = TLSHandshakeFlightDecoder()

    #expect(try decoder.receive(frame: frames[0]).isEmpty)
    #expect(try decoder.receive(frame: frames[1]).isEmpty)
    #expect(try decoder.receive(frame: frames[2]).isEmpty)
    #expect(try decoder.receive(frame: frames[3]) == [message])
}

@Test
func handshakeFlightRejectsInvalidCryptoInput() throws {
    let first = QUICFrame.crypto(offset: 0, data: Data([0x01, 0x00, 0x00, 0x01, 0xaa]))
    let conflicting = QUICFrame.crypto(offset: 4, data: Data([0xbb]))
    var decoder = TLSHandshakeFlightDecoder()

    #expect(try decoder.receive(frame: first) == [
        TLSHandshakeMessage(type: .clientHello, body: Data([0xaa]))
    ])
    try expectThrowing {
        _ = try decoder.receive(frame: conflicting)
    }
    try expectThrowing {
        _ = try decoder.receive(frame: .ping)
    }
    try expectThrowing {
        _ = try TLSHandshakeFlight(messages: [
            TLSHandshakeMessage(type: .clientHello, body: Data([0x01]))
        ]).cryptoFrames(maxFramePayloadBytes: 0)
    }
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

@Test
func tlsQUICConnectionStateRunsHandshakeKeysAndKeyUpdateLifecycle() throws {
    let clientHello = TLSHandshakeMessage(type: .clientHello, body: Data([0x01, 0x02, 0x03]))
    let serverHello = TLSHandshakeMessage(type: .serverHello, body: Data([0x04, 0x05]))
    var state = TLSQUICConnectionState(role: .client)

    let outbound = try state.sendHandshakeFlight(messages: [clientHello], maxFramePayloadBytes: 4)
    #expect(!outbound.isEmpty)
    #expect(state.phase == .handshakeInProgress)

    let inbound = try TLSHandshakeFlight(messages: [serverHello]).cryptoFrames(maxFramePayloadBytes: 4)
    #expect(try state.receiveHandshakeFrames(inbound) == [serverHello])
    var expectedTranscript = Data()
    expectedTranscript.append(try clientHello.encode())
    expectedTranscript.append(try serverHello.encode())
    #expect(state.transcript.encodedMessages == expectedTranscript)

    let handshakeSecrets = try state.deriveHandshakeTrafficSecrets(sharedSecret: Data(repeating: 0x33, count: 32))
    #expect(state.phase == .handshakeKeysReady)
    #expect(handshakeSecrets.clientHandshakeTrafficSecret != handshakeSecrets.serverHandshakeTrafficSecret)

    let applicationSecrets = try state.deriveApplicationTrafficSecrets()
    #expect(state.phase == .applicationKeysReady)
    #expect(state.keyUpdateGeneration == 0)

    let updatedSecrets = try state.updateApplicationTrafficSecrets()
    #expect(state.keyUpdateGeneration == 1)
    #expect(updatedSecrets.clientApplicationTrafficSecret != applicationSecrets.clientApplicationTrafficSecret)
    #expect(updatedSecrets.serverApplicationTrafficSecret != applicationSecrets.serverApplicationTrafficSecret)
}

@Test
func tlsQUICConnectionStateClosesOnPrematureKeyUpdate() throws {
    var state = TLSQUICConnectionState(role: .server)

    try expectThrowing {
        _ = try state.updateApplicationTrafficSecrets()
    }

    #expect(state.phase == .closed)
    #expect(state.closeState.closeFrame == .connectionClose(
        errorCode: QUICTransportErrorCode.keyUpdateError.rawValue,
        frameType: nil,
        reason: Data("key update before application traffic secrets".utf8)
    ))
}

@Test
func tlsQUICConnectionStateMapsApplicationCloseAndFinalSizeErrors() throws {
    var applicationClose = TLSQUICConnectionState(role: .client)
    let closeFrame = applicationClose.closeApplication(errorCode: 0x52e4a40fa8db, reason: "WT_CLOSE_SESSION")
    #expect(applicationClose.phase == .closed)
    #expect(closeFrame == .connectionClose(
        errorCode: 0x52e4a40fa8db,
        frameType: nil,
        reason: Data("WT_CLOSE_SESSION".utf8)
    ))
    #expect(applicationClose.closeApplication(errorCode: 0x01, reason: "late close") == closeFrame)
    try expectThrowing {
        try applicationClose.openStream(id: 4, maxSendOffset: 1, maxReceiveOffset: 1)
    }

    var finalSizeClose = TLSQUICConnectionState(role: .server)
    try finalSizeClose.openStream(id: 0, maxSendOffset: 1_024, maxReceiveOffset: 1_024)
    _ = try finalSizeClose.receiveStreamFrame(.stream(id: 0, offset: 0, fin: true, data: Data([0x01, 0x02])))
    try expectThrowing {
        _ = try finalSizeClose.receiveStreamFrame(.stream(id: 0, offset: 2, fin: false, data: Data([0x03])))
    }

    #expect(finalSizeClose.phase == .closed)
    #expect(finalSizeClose.closeState.closeFrame == .connectionClose(
        errorCode: QUICTransportErrorCode.finalSizeError.rawValue,
        frameType: nil,
        reason: Data("stream state violation: STREAM data exceeds final size".utf8)
    ))
}

private enum PromptFreeCertificateFixture {
    static func makeCertificateDER() throws -> Data {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2_048,
            kSecAttrIsPermanent: false
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? ExpectedThrowError.missingThrow
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw ExpectedThrowError.missingThrow
        }
        guard let publicKeyDER = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error?.takeRetainedValue() ?? ExpectedThrowError.missingThrow
        }

        let signatureAlgorithm = try DERFixture.sequence([
            DERFixture.objectIdentifier([1, 2, 840, 113_549, 1, 1, 11]),
            DERFixture.null()
        ])
        let rsaAlgorithm = try DERFixture.sequence([
            DERFixture.objectIdentifier([1, 2, 840, 113_549, 1, 1, 1]),
            DERFixture.null()
        ])
        let name = DERFixture.sequence([
            DERFixture.set([
                try DERFixture.sequence([
                    DERFixture.objectIdentifier([2, 5, 4, 3]),
                    DERFixture.utf8String("localhost")
                ])
            ])
        ])
        let validity = DERFixture.sequence([
            DERFixture.utcTime(Date(timeIntervalSince1970: 1_700_000_000)),
            DERFixture.utcTime(Date(timeIntervalSince1970: 1_800_000_000))
        ])
        let subjectPublicKeyInfo = DERFixture.sequence([
            rsaAlgorithm,
            DERFixture.bitString(publicKeyDER)
        ])
        let extensions = try DERFixture.explicit(3, DERFixture.sequence([
            DERFixture.sequence([
                DERFixture.objectIdentifier([2, 5, 29, 19]),
                DERFixture.boolean(true),
                DERFixture.octetString(DERFixture.sequence([DERFixture.boolean(false)]))
            ]),
            DERFixture.sequence([
                DERFixture.objectIdentifier([2, 5, 29, 17]),
                DERFixture.octetString(DERFixture.sequence([
                    DERFixture.contextSpecificPrimitive(2, Data("localhost".utf8))
                ]))
            ])
        ]))

        let tbsCertificate = DERFixture.sequence([
            DERFixture.explicit(0, DERFixture.integer(Data([0x02]))),
            DERFixture.integer(Data([0x01])),
            signatureAlgorithm,
            name,
            validity,
            name,
            subjectPublicKeyInfo,
            extensions
        ])
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            tbsCertificate as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? ExpectedThrowError.missingThrow
        }

        return DERFixture.sequence([
            tbsCertificate,
            signatureAlgorithm,
            DERFixture.bitString(signature)
        ])
    }
}

private enum DERFixture {
    static func sequence(_ parts: [Data]) -> Data {
        tagged(0x30, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func set(_ parts: [Data]) -> Data {
        tagged(0x31, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func explicit(_ tag: UInt8, _ content: Data) -> Data {
        tagged(0xa0 + tag, content)
    }

    static func contextSpecificPrimitive(_ tag: UInt8, _ content: Data) -> Data {
        tagged(0x80 + tag, content)
    }

    static func integer(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.count > 1, bytes[0] == 0, bytes[1] < 0x80 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first >= 0x80 {
            bytes.insert(0, at: 0)
        }
        return tagged(0x02, Data(bytes))
    }

    static func boolean(_ value: Bool) -> Data {
        tagged(0x01, Data([value ? 0xff : 0x00]))
    }

    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        tagged(0x03, Data([unusedBits]) + value)
    }

    static func octetString(_ value: Data) -> Data {
        tagged(0x04, value)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
    }

    static func objectIdentifier(_ components: [UInt64]) throws -> Data {
        guard components.count >= 2 else {
            throw ExpectedThrowError.missingThrow
        }
        guard components[0] <= 2, components[1] < 40 || components[0] == 2 else {
            throw ExpectedThrowError.missingThrow
        }
        let rootValue = components[0] * 40 + components[1]
        guard rootValue <= UInt64(UInt8.max) else {
            throw ExpectedThrowError.missingThrow
        }

        var bytes = [UInt8(rootValue)]
        for component in components.dropFirst(2) {
            var encoded = [UInt8(component & 0x7f)]
            var value = component >> 7
            while value > 0 {
                encoded.insert(UInt8(value & 0x7f) | 0x80, at: 0)
                value >>= 7
            }
            bytes.append(contentsOf: encoded)
        }
        return tagged(0x06, Data(bytes))
    }

    static func utf8String(_ value: String) -> Data {
        tagged(0x0c, Data(value.utf8))
    }

    static func utcTime(_ value: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tagged(0x17, Data(formatter.string(from: value).utf8))
    }

    private static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + length(content.count) + content
    }

    private static func length(_ count: Int) -> Data {
        if count < 128 {
            return Data([UInt8(count)])
        }

        var value = count
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
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
