import Foundation
import WebTransportQUICCore

/// The QPACK wire primitives: a prefixed integer and a string literal, readable and writable, plus
/// the length check they both need.
///
/// Module-internal rather than file-private because the stream-instruction codec below lives in its
/// own file and uses them, and because the field-section codecs do too. Call sites are unchanged:
/// they were already in this module, and a private function only differs from an internal one by
/// which files can see it.
func encodeStringLiteral(
    _ bytes: Data,
    prefixBits: UInt8,
    firstBytePrefix: UInt8,
    huffman: Bool
) throws -> Data {
    let encodedBytes = huffman ? QPACKHuffman.encode(bytes) : bytes
    guard encodedBytes.count <= Int(QUICVarInt.maximum) else {
        throw QUICCodecError.valueOutOfRange("QPACK string literal length exceeds range")
    }
    let huffmanPrefix = huffman ? UInt8(1 << prefixBits) : 0
    var output = try encodePrefixedInteger(
        UInt64(encodedBytes.count),
        prefixBits: prefixBits,
        firstBytePrefix: firstBytePrefix | huffmanPrefix
    )
    output.append(encodedBytes)
    return output
}
func decodeStringLiteral(
    from cursor: inout QUICByteCursor,
    prefixBits: UInt8,
    firstByte: UInt8? = nil
) throws -> String {
    let first = try firstByte ?? cursor.readUInt8()
    let huffmanFlag = (first & (1 << prefixBits)) != 0
    let length = try checkedLength(try decodePrefixedInteger(from: &cursor, prefixBits: prefixBits, firstByte: first))
    let bytes = try cursor.readBytes(count: length)
    let decodedBytes = huffmanFlag ? try QPACKHuffman.decode(bytes) : bytes
    guard let value = String(data: decodedBytes, encoding: .utf8) else {
        throw QUICCodecError.malformed("QPACK string literal is not UTF-8")
    }
    return value
}
func checkedLength(_ value: UInt64) throws -> Int {
    guard value <= UInt64(Int.max) else {
        throw QUICCodecError.valueOutOfRange("QPACK length exceeds Int.max")
    }
    return Int(value)
}
func encodePrefixedInteger(
    _ value: UInt64,
    prefixBits: UInt8,
    firstBytePrefix: UInt8
) throws -> Data {
    guard prefixBits > 0, prefixBits <= 8 else {
        throw QUICCodecError.valueOutOfRange("QPACK prefix width must be 1...8 bits")
    }
    let maxPrefixValue = UInt64((1 << prefixBits) - 1)
    guard value <= QUICVarInt.maximum else {
        throw QUICCodecError.valueOutOfRange("QPACK integer exceeds supported range")
    }

    if value < maxPrefixValue {
        return Data([firstBytePrefix | UInt8(value)])
    }

    var output = Data([firstBytePrefix | UInt8(maxPrefixValue)])
    var remainder = value - maxPrefixValue
    while remainder >= 128 {
        output.append(UInt8((remainder % 128) + 128))
        remainder /= 128
    }
    output.append(UInt8(remainder))
    return output
}
func decodePrefixedInteger(
    from cursor: inout QUICByteCursor,
    prefixBits: UInt8,
    firstByte: UInt8? = nil
) throws -> UInt64 {
    guard prefixBits > 0, prefixBits <= 8 else {
        throw QUICCodecError.valueOutOfRange("QPACK prefix width must be 1...8 bits")
    }

    let byte = try firstByte ?? cursor.readUInt8()
    let mask = UInt8((1 << prefixBits) - 1)
    let maxPrefixValue = UInt64(mask)
    var value = UInt64(byte & mask)
    guard value == maxPrefixValue else {
        return value
    }

    var multiplier: UInt64 = 0
    while true {
        let next = try cursor.readUInt8()
        let chunk = UInt64(next & 0x7f)
        guard multiplier < 63 else {
            throw QUICCodecError.valueOutOfRange("QPACK integer shift exceeds UInt64")
        }
        let shifted = chunk << multiplier
        guard shifted <= UInt64.max - value else {
            throw QUICCodecError.valueOutOfRange("QPACK integer overflow")
        }
        value += shifted
        guard (next & 0x80) != 0 else {
            break
        }
        multiplier += 7
    }

    guard value <= QUICVarInt.maximum else {
        throw QUICCodecError.valueOutOfRange("QPACK integer exceeds supported range")
    }
    return value
}
