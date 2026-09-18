import Foundation
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple
@testable import WebTransportNetworkRuntime

enum QUICInitialPacketProtection {
    enum KeyPhase {
        case client
        case server
    }

    struct ParsedLongHeader: Equatable, Sendable {
        var firstByte: UInt8
        var packetType: QUICPacketType
        var version: UInt32
        var destinationConnectionID: Data
        var sourceConnectionID: Data
        var token: Data
        var length: UInt64
        var packetNumberOffset: Int
        var payloadEndOffset: Int
    }

    /// Everything one sealed packet is built from, as a single value.
    ///
    /// A struct rather than ten parameters: they are one packet's header plus its payload,
    /// which is how RFC 9001 describes the sealing input, and ten was over SwiftLint's limit.
    struct SealRequest {
        var packetType: QUICPacketType
        var version: UInt32
        var destinationConnectionID: Data
        var sourceConnectionID: Data
        var token: Data
        var packetNumber: UInt64
        var packetNumberLength: Int
        var plaintextPayload: Data
        var keyPhase: KeyPhase
        var initialSecretConnectionID: Data
    }

    static func seal(_ request: SealRequest) throws -> Data {
        let packetType = request.packetType
        let version = request.version
        let destinationConnectionID = request.destinationConnectionID
        let sourceConnectionID = request.sourceConnectionID
        let token = request.token
        let packetNumber = request.packetNumber
        let packetNumberLength = request.packetNumberLength
        let plaintextPayload = request.plaintextPayload
        let keyPhase = request.keyPhase
        let initialSecretConnectionID = request.initialSecretConnectionID
        guard packetType == .initial else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        guard destinationConnectionID.count <= 20, sourceConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("connection ID length exceeds 20")
        }
        guard (1...4).contains(packetNumberLength) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        let keys = try packetProtectionKeys(for: keyPhase, initialSecretConnectionID: initialSecretConnectionID)
        let packetNumberBytes = try QUICPacketNumber.encodeTruncated(packetNumber, byteCount: packetNumberLength)
        let protectedLength = UInt64(packetNumberBytes.count + plaintextPayload.count + 16)

        var header = Data()
        header.append(UInt8(0xc0) | (packetType.rawValue << 4) | UInt8(packetNumberLength - 1))
        var buffer = QUICByteBuffer()
        buffer.appendUInt32(version)
        header.append(buffer.data)
        header.append(UInt8(destinationConnectionID.count))
        header.append(destinationConnectionID)
        header.append(UInt8(sourceConnectionID.count))
        header.append(sourceConnectionID)
        header.append(try QUICVarInt.encode(UInt64(token.count)))
        header.append(token)
        header.append(try QUICVarInt.encode(protectedLength))
        let packetNumberOffset = header.count
        header.append(packetNumberBytes)

        let ciphertextAndTag = try QUICPacketProtection.seal(
            plaintext: plaintextPayload,
            packetNumber: packetNumber,
            associatedData: header,
            keys: keys
        )
        return try applyHeaderProtection(
            headerAndCiphertext: header + ciphertextAndTag,
            packetNumberOffset: packetNumberOffset,
            packetNumberLength: packetNumberLength,
            headerProtectionKey: keys.headerProtectionKey
        )
    }

    static func open(
        _ data: Data,
        keyPhase: KeyPhase,
        initialSecretConnectionID: Data,
        parsedHeader: ParsedLongHeader? = nil
    ) throws -> QUICLongHeaderPacket {
        let parsed = try parsedHeader ?? parseProtectedLongHeader(data)
        guard parsed.packetType == .initial else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }

        let keys = try packetProtectionKeys(for: keyPhase, initialSecretConnectionID: initialSecretConnectionID)
        var unprotected = data
        try removeHeaderProtection(
            packet: &unprotected,
            packetNumberOffset: parsed.packetNumberOffset,
            headerProtectionKey: keys.headerProtectionKey
        )
        let packetNumberLength = Int(unprotected[0] & 0x03) + 1
        guard parsed.length >= UInt64(packetNumberLength + 16) else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        guard parsed.packetNumberOffset + packetNumberLength <= parsed.payloadEndOffset,
            parsed.payloadEndOffset <= unprotected.count
        else {
            throw QUICCodecError.truncated(
                needed: parsed.payloadEndOffset,
                available: unprotected.count
            )
        }

        let packetNumberBytes = unprotected[parsed.packetNumberOffset..<(parsed.packetNumberOffset + packetNumberLength)]
        let truncatedPacketNumber = packetNumberBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let packetNumber = try QUICPacketNumber.decodeTruncated(
            truncatedPacketNumber,
            byteCount: packetNumberLength,
            largestAcknowledged: nil
        )
        let ciphertextOffset = parsed.packetNumberOffset + packetNumberLength
        let associatedData = Data(unprotected[..<ciphertextOffset])
        let ciphertextAndTag = Data(unprotected[ciphertextOffset..<parsed.payloadEndOffset])
        let plaintextPayload = try QUICPacketProtection.open(
            ciphertextAndTag: ciphertextAndTag,
            packetNumber: packetNumber,
            associatedData: associatedData,
            keys: keys
        )

        return QUICLongHeaderPacket(
            packetType: parsed.packetType,
            version: parsed.version,
            destinationConnectionID: parsed.destinationConnectionID,
            sourceConnectionID: parsed.sourceConnectionID,
            token: parsed.token,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: plaintextPayload
        )
    }

    static func parseProtectedLongHeader(_ data: Data) throws -> ParsedLongHeader {
        guard data.count >= 7 else {
            throw QUICCodecError.truncated(needed: 7, available: data.count)
        }
        var offset = 0
        let first = data[offset]
        offset += 1
        guard (first & 0x80) != 0 else {
            throw QUICCodecError.malformed("not a long header packet")
        }
        guard let packetType = QUICPacketType(rawValue: (first >> 4) & 0x03),
            packetType == .initial
        else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let version = try readUInt32(data, offset: &offset)
        let destinationLength = Int(try readUInt8(data, offset: &offset))
        guard destinationLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        let destinationConnectionID = try readBytes(data, offset: &offset, count: destinationLength)
        let sourceLength = Int(try readUInt8(data, offset: &offset))
        guard sourceLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        let sourceConnectionID = try readBytes(data, offset: &offset, count: sourceLength)
        let tokenLength = try checkedLength(try readVarInt(data, offset: &offset))
        let token = try readBytes(data, offset: &offset, count: tokenLength)
        let length = try readVarInt(data, offset: &offset)
        let packetNumberOffset = offset
        guard length <= UInt64(data.count - packetNumberOffset) else {
            throw QUICCodecError.malformed("invalid protected packet length")
        }
        let payloadEndOffset = packetNumberOffset + Int(length)
        guard packetNumberOffset + 4 + 16 <= data.count else {
            throw QUICCodecError.truncated(needed: packetNumberOffset + 20, available: data.count)
        }
        return ParsedLongHeader(
            firstByte: first,
            packetType: packetType,
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: token,
            length: length,
            packetNumberOffset: packetNumberOffset,
            payloadEndOffset: payloadEndOffset
        )
    }

    private static func packetProtectionKeys(
        for keyPhase: KeyPhase,
        initialSecretConnectionID: Data
    ) throws -> QUICPacketProtectionKeys {
        let secrets = try QUICInitialKeyDerivation.deriveVersion1Secrets(
            destinationConnectionID: initialSecretConnectionID
        )
        switch keyPhase {
        case .client:
            return QUICPacketProtectionKeys(
                key: secrets.clientKey,
                iv: secrets.clientIV,
                headerProtectionKey: secrets.clientHeaderProtectionKey
            )
        case .server:
            return QUICPacketProtectionKeys(
                key: secrets.serverKey,
                iv: secrets.serverIV,
                headerProtectionKey: secrets.serverHeaderProtectionKey
            )
        }
    }

    static func applyHeaderProtection(
        headerAndCiphertext: Data,
        packetNumberOffset: Int,
        packetNumberLength: Int,
        headerProtectionKey: Data
    ) throws -> Data {
        guard packetNumberOffset + 4 + 16 <= headerAndCiphertext.count else {
            throw QUICCodecError.truncated(
                needed: packetNumberOffset + 20,
                available: headerAndCiphertext.count
            )
        }
        var output = headerAndCiphertext
        let sampleStart = packetNumberOffset + 4
        let sample = Data(output[sampleStart..<(sampleStart + 16)])
        let mask = try QUICPacketProtection.headerProtectionMask(
            sample: sample,
            headerProtectionKey: headerProtectionKey
        )
        output[0] ^= mask[0] & 0x0f
        for index in 0..<packetNumberLength {
            output[packetNumberOffset + index] ^= mask[index + 1]
        }
        return output
    }

    static func removeHeaderProtection(
        packet: inout Data,
        packetNumberOffset: Int,
        headerProtectionKey: Data
    ) throws {
        guard packetNumberOffset + 4 + 16 <= packet.count else {
            throw QUICCodecError.truncated(
                needed: packetNumberOffset + 20,
                available: packet.count
            )
        }
        let sampleStart = packetNumberOffset + 4
        let sample = Data(packet[sampleStart..<(sampleStart + 16)])
        let mask = try QUICPacketProtection.headerProtectionMask(
            sample: sample,
            headerProtectionKey: headerProtectionKey
        )
        packet[0] ^= mask[0] & 0x0f
        let packetNumberLength = Int(packet[0] & 0x03) + 1
        guard packetNumberOffset + packetNumberLength <= packet.count else {
            throw QUICCodecError.truncated(
                needed: packetNumberOffset + packetNumberLength,
                available: packet.count
            )
        }
        for index in 0..<packetNumberLength {
            packet[packetNumberOffset + index] ^= mask[index + 1]
        }
    }

    private static func readUInt8(_ data: Data, offset: inout Int) throws -> UInt8 {
        guard offset < data.count else {
            throw QUICCodecError.truncated(needed: offset + 1, available: data.count)
        }
        defer { offset += 1 }
        return data[offset]
    }

    private static func readUInt32(_ data: Data, offset: inout Int) throws -> UInt32 {
        let bytes = try readBytes(data, offset: &offset, count: 4)
        return bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    private static func readBytes(_ data: Data, offset: inout Int, count: Int) throws -> Data {
        guard count >= 0 else {
            throw QUICCodecError.valueOutOfRange("negative byte count")
        }
        guard offset + count <= data.count else {
            throw QUICCodecError.truncated(needed: offset + count, available: data.count)
        }
        let end = offset + count
        defer { offset = end }
        return Data(data[offset..<end])
    }

    private static func readVarInt(_ data: Data, offset: inout Int) throws -> UInt64 {
        let first = try readUInt8(data, offset: &offset)
        let length = 1 << Int(first >> 6)
        var value = UInt64(first & 0x3f)
        guard length > 1 else {
            return value
        }
        for _ in 1..<length {
            value = (value << 8) | UInt64(try readUInt8(data, offset: &offset))
        }
        return value
    }

    private static func checkedLength(_ value: UInt64) throws -> Int {
        guard value <= UInt64(Int.max) else {
            throw QUICCodecError.valueOutOfRange("length exceeds Int.max")
        }
        return Int(value)
    }
}
