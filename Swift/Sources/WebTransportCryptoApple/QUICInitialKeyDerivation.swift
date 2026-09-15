import CryptoKit
import Foundation
import WebTransportQUICCore

public struct QUICInitialSecrets: Equatable, Sendable {
    public var initialSecret: Data
    public var clientInitialSecret: Data
    public var serverInitialSecret: Data
    public var clientKey: Data
    public var serverKey: Data
    public var clientIV: Data
    public var serverIV: Data
    public var clientHeaderProtectionKey: Data
    public var serverHeaderProtectionKey: Data
}

public enum QUICInitialKeyDerivation {
    public static let version1InitialSalt = Data([
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a,
    ])

    public static func deriveVersion1Secrets(destinationConnectionID: Data) throws -> QUICInitialSecrets {
        let initialSecret = hkdfExtract(
            inputKeyMaterial: destinationConnectionID,
            salt: version1InitialSalt
        )
        let clientInitialSecret = try hkdfExpandLabel(
            secret: initialSecret,
            label: "client in",
            outputByteCount: 32
        )
        let serverInitialSecret = try hkdfExpandLabel(
            secret: initialSecret,
            label: "server in",
            outputByteCount: 32
        )

        return QUICInitialSecrets(
            initialSecret: initialSecret,
            clientInitialSecret: clientInitialSecret,
            serverInitialSecret: serverInitialSecret,
            clientKey: try hkdfExpandLabel(secret: clientInitialSecret, label: "quic key", outputByteCount: 16),
            serverKey: try hkdfExpandLabel(secret: serverInitialSecret, label: "quic key", outputByteCount: 16),
            clientIV: try hkdfExpandLabel(secret: clientInitialSecret, label: "quic iv", outputByteCount: 12),
            serverIV: try hkdfExpandLabel(secret: serverInitialSecret, label: "quic iv", outputByteCount: 12),
            clientHeaderProtectionKey: try hkdfExpandLabel(secret: clientInitialSecret, label: "quic hp", outputByteCount: 16),
            serverHeaderProtectionKey: try hkdfExpandLabel(secret: serverInitialSecret, label: "quic hp", outputByteCount: 16)
        )
    }

    static func hkdfExtract(inputKeyMaterial: Data, salt: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(
            for: inputKeyMaterial,
            using: SymmetricKey(data: salt)
        )
        return Data(mac)
    }

    static func hkdfExpandLabel(secret: Data, label: String, outputByteCount: Int) throws -> Data {
        // RFC 5869 section 2.3 caps L at 255 * HashLen, which is 255 * 32 for the
        // SHA-256 this module uses. The expand loop's block counter is one byte, so
        // a longer request wraps it to zero and the output silently stops being the
        // RFC's HKDF stream while every guard passes. A negative count is refused
        // too: `prefix(_:)` traps on it. TLS13KeySchedule.hkdfExpandLabel carries
        // the same bound.
        guard outputByteCount >= 0, outputByteCount <= 255 * 32 else {
            throw QUICCodecError.valueOutOfRange(
                "HKDF output must be 0...\(255 * 32) bytes for SHA-256 (RFC 5869 section 2.3)"
            )
        }

        let fullLabel = "tls13 " + label
        guard fullLabel.utf8.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("HKDF label too large")
        }

        var info = Data()
        info.append(UInt8((outputByteCount >> 8) & 0xff))
        info.append(UInt8(outputByteCount & 0xff))
        info.append(UInt8(fullLabel.utf8.count))
        info.append(contentsOf: fullLabel.utf8)
        info.append(0x00)

        return hkdfExpand(pseudoRandomKey: secret, info: info, outputByteCount: outputByteCount)
    }

    static func hkdfExpand(pseudoRandomKey: Data, info: Data, outputByteCount: Int) -> Data {
        var output = Data()
        var previous = Data()
        var counter: UInt8 = 1

        while output.count < outputByteCount {
            var input = Data()
            input.append(previous)
            input.append(info)
            input.append(counter)

            let mac = HMAC<SHA256>.authenticationCode(
                for: input,
                using: SymmetricKey(data: pseudoRandomKey)
            )
            previous = Data(mac)
            output.append(previous)
            counter &+= 1
        }

        return output.prefix(outputByteCount)
    }
}
