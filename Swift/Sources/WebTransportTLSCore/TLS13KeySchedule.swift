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
        guard outputByteCount <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("HKDF output too large")
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
    public private(set) var encodedMessages: Data

    public init() {
        self.encodedMessages = Data()
    }

    public mutating func append(_ message: TLSHandshakeMessage) throws {
        encodedMessages.append(try message.encode())
    }

    public var hash: Data {
        TLS13KeySchedule.transcriptHash(encodedMessages)
    }
}
