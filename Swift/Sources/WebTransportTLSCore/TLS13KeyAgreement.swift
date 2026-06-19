import CryptoKit
import Foundation
import WebTransportQUICCore

public struct TLS13HandshakeTrafficSecrets: Equatable, Sendable {
    public var clientHandshakeTrafficSecret: Data
    public var serverHandshakeTrafficSecret: Data

    public init(clientHandshakeTrafficSecret: Data, serverHandshakeTrafficSecret: Data) {
        self.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret
        self.serverHandshakeTrafficSecret = serverHandshakeTrafficSecret
    }
}

public struct TLS13ApplicationTrafficSecrets: Equatable, Sendable {
    public var clientApplicationTrafficSecret: Data
    public var serverApplicationTrafficSecret: Data

    public init(clientApplicationTrafficSecret: Data, serverApplicationTrafficSecret: Data) {
        self.clientApplicationTrafficSecret = clientApplicationTrafficSecret
        self.serverApplicationTrafficSecret = serverApplicationTrafficSecret
    }
}

public enum TLS13KeyAgreement {
    public static func makeX25519PrivateKey() -> Curve25519.KeyAgreement.PrivateKey {
        Curve25519.KeyAgreement.PrivateKey()
    }

    public static func x25519KeyShare(
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> TLSKeyShareEntry {
        let rawKey = publicKey.rawRepresentation
        guard rawKey.count == 32 else {
            throw QUICCodecError.malformed("X25519 public key must be 32 bytes")
        }
        return TLSKeyShareEntry(group: TLSNamedGroup.x25519, keyExchange: rawKey)
    }

    public static func x25519SharedSecret(
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        peerShare: TLSKeyShareEntry
    ) throws -> Data {
        guard peerShare.group == TLSNamedGroup.x25519 else {
            throw QUICCodecError.malformed("peer key_share group is not X25519")
        }
        guard peerShare.keyExchange.count == 32 else {
            throw QUICCodecError.malformed("X25519 peer key_share must be 32 bytes")
        }

        let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerShare.keyExchange)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    public static func handshakeSecret(sharedSecret: Data, earlySecret: Data? = nil) throws -> Data {
        let baseEarlySecret = earlySecret ?? noPSKEarlySecret
        let derived = try TLS13KeySchedule.deriveSecret(
            secret: baseEarlySecret,
            label: "derived",
            transcriptHash: TLS13KeySchedule.transcriptHash(Data())
        )
        return TLS13KeySchedule.hkdfExtract(inputKeyMaterial: sharedSecret, salt: derived)
    }

    public static func handshakeTrafficSecrets(
        handshakeSecret: Data,
        transcriptHash: Data
    ) throws -> TLS13HandshakeTrafficSecrets {
        TLS13HandshakeTrafficSecrets(
            clientHandshakeTrafficSecret: try TLS13KeySchedule.deriveSecret(
                secret: handshakeSecret,
                label: "c hs traffic",
                transcriptHash: transcriptHash
            ),
            serverHandshakeTrafficSecret: try TLS13KeySchedule.deriveSecret(
                secret: handshakeSecret,
                label: "s hs traffic",
                transcriptHash: transcriptHash
            )
        )
    }

    public static func masterSecret(handshakeSecret: Data) throws -> Data {
        let derived = try TLS13KeySchedule.deriveSecret(
            secret: handshakeSecret,
            label: "derived",
            transcriptHash: TLS13KeySchedule.transcriptHash(Data())
        )
        return TLS13KeySchedule.hkdfExtract(inputKeyMaterial: zeroSecret, salt: derived)
    }

    public static func applicationTrafficSecrets(
        masterSecret: Data,
        transcriptHash: Data
    ) throws -> TLS13ApplicationTrafficSecrets {
        TLS13ApplicationTrafficSecrets(
            clientApplicationTrafficSecret: try TLS13KeySchedule.deriveSecret(
                secret: masterSecret,
                label: "c ap traffic",
                transcriptHash: transcriptHash
            ),
            serverApplicationTrafficSecret: try TLS13KeySchedule.deriveSecret(
                secret: masterSecret,
                label: "s ap traffic",
                transcriptHash: transcriptHash
            )
        )
    }

    public static func nextApplicationTrafficSecret(_ trafficSecret: Data) throws -> Data {
        try TLS13KeySchedule.hkdfExpandLabel(
            secret: trafficSecret,
            label: "traffic upd",
            outputByteCount: TLS13KeySchedule.sha256Length
        )
    }

    public static var zeroSecret: Data {
        Data(repeating: 0, count: TLS13KeySchedule.sha256Length)
    }

    public static var noPSKEarlySecret: Data {
        TLS13KeySchedule.hkdfExtract(inputKeyMaterial: zeroSecret, salt: zeroSecret)
    }
}
