import Foundation
import Testing
import WebTransportCryptoApple
import WebTransportTLSCore

@Test
func derivesRFC9001InitialSecretVector() throws {
    let secrets = try QUICInitialKeyDerivation.deriveVersion1Secrets(
        destinationConnectionID: try Data(hex: "8394c8f03e515708")
    )

    let clientInitialSecret = try Data(hex: "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    let clientKey = try Data(hex: "1f369613dd76d5467730efcbe3b1a22d")
    let clientIV = try Data(hex: "fa044b2f42a3fd3b46fb255c")
    let clientHeaderProtectionKey = try Data(hex: "9f50449e04a0e810283a1e9933adedd2")
    let serverInitialSecret = try Data(hex: "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    let serverKey = try Data(hex: "cf3a5331653c364c88f0f379b6067e37")
    let serverIV = try Data(hex: "0ac1493ca1905853b0bba03e")
    let serverHeaderProtectionKey = try Data(hex: "c206b8d9b9f0f37644430b490eeaa314")

    #expect(secrets.clientInitialSecret == clientInitialSecret)
    #expect(secrets.clientKey == clientKey)
    #expect(secrets.clientIV == clientIV)
    #expect(secrets.clientHeaderProtectionKey == clientHeaderProtectionKey)
    #expect(secrets.serverInitialSecret == serverInitialSecret)
    #expect(secrets.serverKey == serverKey)
    #expect(secrets.serverIV == serverIV)
    #expect(secrets.serverHeaderProtectionKey == serverHeaderProtectionKey)
}

@Test
func derivesRFC9001ClientHeaderProtectionMaskVector() throws {
    let mask = try QUICPacketProtection.headerProtectionMask(
        sample: try Data(hex: "d1b1c98dd7689fb8ec11d242b123dc9b"),
        headerProtectionKey: try Data(hex: "9f50449e04a0e810283a1e9933adedd2")
    )
    let expected = try Data(hex: "437b9aec36")

    #expect(mask == expected)
}

@Test
func packetProtectionSealsAndOpensHandshakeStylePayload() throws {
    let handshakeKeys = try QUICPacketProtection.deriveKeys(
        trafficSecret: try Data(hex: "1111111111111111111111111111111111111111111111111111111111111111")
    )
    let associatedData = Data("handshake-header".utf8)
    let plaintext = Data("handshake protected payload".utf8)

    let sealed = try QUICPacketProtection.seal(
        plaintext: plaintext,
        packetNumber: 4,
        associatedData: associatedData,
        keys: handshakeKeys
    )
    let opened = try QUICPacketProtection.open(
        ciphertextAndTag: sealed,
        packetNumber: 4,
        associatedData: associatedData,
        keys: handshakeKeys
    )
    #expect(sealed != plaintext)
    #expect(opened == plaintext)
}

@Test
func packetProtectionAcceptsTLSHandshakeTrafficSecret() throws {
    let clientPrivateKey = TLS13KeyAgreement.makeX25519PrivateKey()
    let serverPrivateKey = TLS13KeyAgreement.makeX25519PrivateKey()
    let clientShare = try TLS13KeyAgreement.x25519KeyShare(publicKey: clientPrivateKey.publicKey)
    let serverShare = try TLS13KeyAgreement.x25519KeyShare(publicKey: serverPrivateKey.publicKey)
    let sharedSecret = try TLS13KeyAgreement.x25519SharedSecret(
        privateKey: clientPrivateKey,
        peerShare: serverShare
    )
    let peerSharedSecret = try TLS13KeyAgreement.x25519SharedSecret(
        privateKey: serverPrivateKey,
        peerShare: clientShare
    )
    #expect(sharedSecret == peerSharedSecret)

    let handshakeSecret = try TLS13KeyAgreement.handshakeSecret(sharedSecret: sharedSecret)
    let trafficSecrets = try TLS13KeyAgreement.handshakeTrafficSecrets(
        handshakeSecret: handshakeSecret,
        transcriptHash: TLS13KeySchedule.transcriptHash(Data("client-server-hello".utf8))
    )
    let keys = try QUICPacketProtection.deriveKeys(
        trafficSecret: trafficSecrets.serverHandshakeTrafficSecret
    )
    let associatedData = Data("server-handshake-header".utf8)
    let plaintext = Data("server encrypted handshake bytes".utf8)
    let sealed = try QUICPacketProtection.seal(
        plaintext: plaintext,
        packetNumber: 7,
        associatedData: associatedData,
        keys: keys
    )

    #expect(try QUICPacketProtection.open(
        ciphertextAndTag: sealed,
        packetNumber: 7,
        associatedData: associatedData,
        keys: keys
    ) == plaintext)
}

@Test
func packetProtectionAcceptsTLSApplicationTrafficSecret() throws {
    let handshakeSecret = try TLS13KeyAgreement.handshakeSecret(
        sharedSecret: Data(repeating: 0x44, count: TLS13KeySchedule.sha256Length)
    )
    let masterSecret = try TLS13KeyAgreement.masterSecret(handshakeSecret: handshakeSecret)
    let applicationSecrets = try TLS13KeyAgreement.applicationTrafficSecrets(
        masterSecret: masterSecret,
        transcriptHash: TLS13KeySchedule.transcriptHash(Data("finished-handshake-transcript".utf8))
    )
    let keys = try QUICPacketProtection.deriveKeys(
        trafficSecret: applicationSecrets.clientApplicationTrafficSecret
    )
    let associatedData = Data("short-header".utf8)
    let plaintext = Data("1rtt application payload".utf8)
    let sealed = try QUICPacketProtection.seal(
        plaintext: plaintext,
        packetNumber: 11,
        associatedData: associatedData,
        keys: keys
    )

    #expect(try QUICPacketProtection.open(
        ciphertextAndTag: sealed,
        packetNumber: 11,
        associatedData: associatedData,
        keys: keys
    ) == plaintext)
}

@Test
func packetProtectionRejectsTamperedAssociatedData() throws {
    let oneRTTKeys = try QUICPacketProtection.deriveKeys(
        trafficSecret: try Data(hex: "2222222222222222222222222222222222222222222222222222222222222222")
    )
    let plaintext = Data("1rtt protected payload".utf8)
    let sealed = try QUICPacketProtection.seal(
        plaintext: plaintext,
        packetNumber: 12,
        associatedData: Data("1rtt-header".utf8),
        keys: oneRTTKeys
    )

    #expect(throws: Error.self) {
        _ = try QUICPacketProtection.open(
            ciphertextAndTag: sealed,
            packetNumber: 12,
            associatedData: Data("tampered-header".utf8),
            keys: oneRTTKeys
        )
    }
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
