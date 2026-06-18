import CommonCrypto
import CryptoKit
import Foundation
import WebTransportQUICCore

public struct QUICPacketProtectionKeys: Equatable, Sendable {
    public var key: Data
    public var iv: Data
    public var headerProtectionKey: Data

    public init(key: Data, iv: Data, headerProtectionKey: Data) {
        self.key = key
        self.iv = iv
        self.headerProtectionKey = headerProtectionKey
    }
}

public enum QUICPacketProtection {
    public static func deriveKeys(
        trafficSecret: Data,
        keyByteCount: Int = 16,
        ivByteCount: Int = 12,
        headerProtectionKeyByteCount: Int = 16
    ) throws -> QUICPacketProtectionKeys {
        QUICPacketProtectionKeys(
            key: try QUICInitialKeyDerivation.hkdfExpandLabel(
                secret: trafficSecret,
                label: "quic key",
                outputByteCount: keyByteCount
            ),
            iv: try QUICInitialKeyDerivation.hkdfExpandLabel(
                secret: trafficSecret,
                label: "quic iv",
                outputByteCount: ivByteCount
            ),
            headerProtectionKey: try QUICInitialKeyDerivation.hkdfExpandLabel(
                secret: trafficSecret,
                label: "quic hp",
                outputByteCount: headerProtectionKeyByteCount
            )
        )
    }

    public static func nonce(iv: Data, packetNumber: UInt64) throws -> Data {
        guard iv.count == 12 else {
            throw QUICCodecError.malformed("QUIC packet protection IV must be 12 bytes")
        }

        var nonce = Array(iv)
        for index in 0..<8 {
            let shift = UInt64((7 - index) * 8)
            nonce[nonce.count - 8 + index] ^= UInt8((packetNumber >> shift) & 0xff)
        }
        return Data(nonce)
    }

    public static func seal(
        plaintext: Data,
        packetNumber: UInt64,
        associatedData: Data,
        keys: QUICPacketProtectionKeys
    ) throws -> Data {
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: keys.key),
            nonce: AES.GCM.Nonce(data: nonce(iv: keys.iv, packetNumber: packetNumber)),
            authenticating: associatedData
        )

        var output = Data(sealedBox.ciphertext)
        output.append(sealedBox.tag)
        return output
    }

    public static func open(
        ciphertextAndTag: Data,
        packetNumber: UInt64,
        associatedData: Data,
        keys: QUICPacketProtectionKeys
    ) throws -> Data {
        guard ciphertextAndTag.count >= 16 else {
            throw QUICCodecError.truncated(needed: 16, available: ciphertextAndTag.count)
        }

        let ciphertext = Data(ciphertextAndTag.dropLast(16))
        let tag = Data(ciphertextAndTag.suffix(16))
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce(iv: keys.iv, packetNumber: packetNumber)),
            ciphertext: ciphertext,
            tag: tag
        )
        return try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: keys.key),
            authenticating: associatedData
        )
    }

    public static func headerProtectionMask(sample: Data, headerProtectionKey: Data) throws -> Data {
        guard sample.count == kCCBlockSizeAES128 else {
            throw QUICCodecError.malformed("AES header protection sample must be 16 bytes")
        }
        guard headerProtectionKey.count == kCCKeySizeAES128 else {
            throw QUICCodecError.malformed("AES-128 header protection key must be 16 bytes")
        }

        var encrypted = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        var encryptedLength = 0
        let status = headerProtectionKey.withUnsafeBytes { keyBytes in
            sample.withUnsafeBytes { sampleBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyBytes.baseAddress,
                    headerProtectionKey.count,
                    nil,
                    sampleBytes.baseAddress,
                    sample.count,
                    &encrypted,
                    encrypted.count,
                    &encryptedLength
                )
            }
        }

        guard status == kCCSuccess else {
            throw QUICCodecError.malformed("CommonCrypto AES header protection failed with status \(status)")
        }
        guard encryptedLength >= 5 else {
            throw QUICCodecError.truncated(needed: 5, available: encryptedLength)
        }
        return Data(encrypted.prefix(5))
    }
}
