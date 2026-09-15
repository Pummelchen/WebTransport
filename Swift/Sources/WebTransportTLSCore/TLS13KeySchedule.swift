import CryptoKit
import Foundation
import WebTransportQUICCore

public struct TLS13TrafficKeys: Equatable, Sendable {
    public var key: Data
    public var iv: Data

    public init(key: Data, iv: Data) {
        self.key = key
        self.iv = iv
    }
}

public enum TLS13KeySchedule {
    public static let sha256Length = 32

    public static func transcriptHash(_ messages: Data) -> Data {
        Data(SHA256.hash(data: messages))
    }

    public static func hkdfExtract(inputKeyMaterial: Data, salt: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(
            for: inputKeyMaterial,
            using: SymmetricKey(data: salt)
        )
        return Data(mac)
    }

    public static func hkdfExpandLabel(
        secret: Data,
        label: String,
        context: Data = Data(),
        outputByteCount: Int
    ) throws -> Data {
        // RFC 5869 section 2.3 caps L at 255 * HashLen. The schedule only uses SHA-256,
        // so anything above 8160 bytes cannot be produced by the defined construction:
        // the block counter would wrap to zero and the output would silently stop being
        // the RFC's HKDF stream while still looking well-formed to a caller.
        guard outputByteCount >= 0, outputByteCount <= 255 * sha256Length else {
            throw QUICCodecError.valueOutOfRange(
                "HKDF output must be 0...\(255 * sha256Length) bytes for SHA-256 (RFC 5869 section 2.3)"
            )
        }

        let fullLabel = "tls13 " + label
        guard fullLabel.utf8.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("HKDF label too large")
        }
        guard context.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("HKDF context too large")
        }

        var info = Data()
        info.append(UInt8((outputByteCount >> 8) & 0xff))
        info.append(UInt8(outputByteCount & 0xff))
        info.append(UInt8(fullLabel.utf8.count))
        info.append(contentsOf: fullLabel.utf8)
        info.append(UInt8(context.count))
        info.append(context)

        return hkdfExpand(pseudoRandomKey: secret, info: info, outputByteCount: outputByteCount)
    }

    public static func deriveSecret(secret: Data, label: String, transcriptHash: Data) throws -> Data {
        try hkdfExpandLabel(
            secret: secret,
            label: label,
            context: transcriptHash,
            outputByteCount: sha256Length
        )
    }

    public static func finishedKey(baseKey: Data) throws -> Data {
        try hkdfExpandLabel(
            secret: baseKey,
            label: "finished",
            outputByteCount: sha256Length
        )
    }

    public static func finishedVerifyData(baseKey: Data, transcriptHash: Data) throws -> Data {
        let key = try finishedKey(baseKey: baseKey)
        let mac = HMAC<SHA256>.authenticationCode(
            for: transcriptHash,
            using: SymmetricKey(data: key)
        )
        return Data(mac)
    }

    public static func trafficKeys(
        trafficSecret: Data,
        keyByteCount: Int = 16,
        ivByteCount: Int = 12
    ) throws -> TLS13TrafficKeys {
        TLS13TrafficKeys(
            key: try hkdfExpandLabel(
                secret: trafficSecret,
                label: "key",
                outputByteCount: keyByteCount
            ),
            iv: try hkdfExpandLabel(
                secret: trafficSecret,
                label: "iv",
                outputByteCount: ivByteCount
            )
        )
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

public struct TLS13Transcript: Equatable, Sendable {
    /// Ceiling on the retained transcript bytes.
    ///
    /// The handshake transcript has to be kept to derive Finished and
    /// CertificateVerify material, but nothing bounded how much of it a peer could
    /// make this endpoint hold: a peer that kept sending well-formed handshake
    /// messages grew it for the connection's lifetime. The CRYPTO reassembler
    /// already caps a single handshake message at roughly its own
    /// `defaultMaximumBufferedBytes`, so this ceiling allows many such messages
    /// while still bounding retention.
    public static let defaultMaximumEncodedBytes = 1024 * 1024

    public private(set) var encodedMessages: Data
    public let maximumEncodedBytes: Int

    public init(maximumEncodedBytes: Int = TLS13Transcript.defaultMaximumEncodedBytes) {
        self.encodedMessages = Data()
        self.maximumEncodedBytes = max(1, maximumEncodedBytes)
    }

    public mutating func append(_ message: TLSHandshakeMessage) throws {
        let encoded = try message.encode()
        guard encoded.count <= maximumEncodedBytes,
            encodedMessages.count <= maximumEncodedBytes - encoded.count
        else {
            throw QUICCodecError.valueOutOfRange(
                "TLS transcript exceeds \(maximumEncodedBytes) bytes"
            )
        }
        encodedMessages.append(encoded)
    }

    public var hash: Data {
        TLS13KeySchedule.transcriptHash(encodedMessages)
    }
}
