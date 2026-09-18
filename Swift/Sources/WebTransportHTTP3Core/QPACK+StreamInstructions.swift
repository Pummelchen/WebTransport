import Foundation
import WebTransportQUICCore

/// The QPACK encoder- and decoder-stream instructions: writing them and applying them to a table.
///
/// Here rather than in `QPACK.swift` because they are a codec of their own -- the two streams a
/// peer uses to update a dynamic table -- and because the primitives they build on now live in
/// `QPACKPrimitives.swift`, so nothing in this file is file-private to another.
extension QPACK {
    public static func encodeEncoderStreamInstructions(
        _ instructions: [QPACKEncoderStreamInstruction],
        huffman: Bool = false
    ) throws -> Data {
        var output = Data()
        for instruction in instructions {
            output.append(try encodeEncoderStreamInstruction(instruction, huffman: huffman))
        }
        return output
    }

    public static func decodeEncoderStreamInstructions(_ data: Data) throws -> [QPACKEncoderStreamInstruction] {
        var cursor = QUICByteCursor(data)
        var instructions: [QPACKEncoderStreamInstruction] = []
        while !cursor.isAtEnd {
            instructions.append(try decodeEncoderStreamInstruction(from: &cursor))
        }
        return instructions
    }

    public static func applyEncoderStream(
        _ data: Data,
        to dynamicTable: inout QPACKDynamicTable
    ) throws -> [HTTPFieldLine] {
        let instructions = try decodeEncoderStreamInstructions(data)
        var insertedFields: [HTTPFieldLine] = []
        for instruction in instructions {
            if let field = try dynamicTable.apply(instruction) {
                insertedFields.append(field)
            }
        }
        return insertedFields
    }

    public static func encodeDecoderStreamInstructions(_ instructions: [QPACKDecoderStreamInstruction]) throws -> Data {
        var output = Data()
        for instruction in instructions {
            output.append(try encodeDecoderStreamInstruction(instruction))
        }
        return output
    }

    public static func decodeDecoderStreamInstructions(_ data: Data) throws -> [QPACKDecoderStreamInstruction] {
        var cursor = QUICByteCursor(data)
        var instructions: [QPACKDecoderStreamInstruction] = []
        while !cursor.isAtEnd {
            instructions.append(try decodeDecoderStreamInstruction(from: &cursor))
        }
        return instructions
    }

    static func decodeEncoderStreamInstruction(
        from cursor: inout QUICByteCursor
    ) throws -> QPACKEncoderStreamInstruction {
        let first = try cursor.readUInt8()
        if (first & 0x80) != 0 {
            let index = try decodePrefixedInteger(from: &cursor, prefixBits: 6, firstByte: first)
            let reference: QPACKNameReference =
                (first & 0x40) != 0
                ? .staticTable(index: index)
                : .dynamicTable(relativeIndex: index)
            let value = try decodeStringLiteral(from: &cursor, prefixBits: 7)
            return .insertWithNameReference(name: reference, value: value)
        }
        if (first & 0x40) != 0 {
            let name = try decodeStringLiteral(from: &cursor, prefixBits: 5, firstByte: first)
            let value = try decodeStringLiteral(from: &cursor, prefixBits: 7)
            return .insertWithLiteralName(name: name, value: value)
        }
        if (first & 0x20) != 0 {
            let capacity = try checkedLength(try decodePrefixedInteger(from: &cursor, prefixBits: 5, firstByte: first))
            return .setDynamicTableCapacity(capacity)
        }
        let relativeIndex = try decodePrefixedInteger(from: &cursor, prefixBits: 5, firstByte: first)
        return .duplicate(relativeIndex: relativeIndex)
    }

    static func decodeDecoderStreamInstruction(
        from cursor: inout QUICByteCursor
    ) throws -> QPACKDecoderStreamInstruction {
        let first = try cursor.readUInt8()
        if (first & 0x80) != 0 {
            return .sectionAcknowledgement(
                streamID: try decodePrefixedInteger(from: &cursor, prefixBits: 7, firstByte: first)
            )
        }
        if (first & 0x40) != 0 {
            return .streamCancellation(
                streamID: try decodePrefixedInteger(from: &cursor, prefixBits: 6, firstByte: first)
            )
        }
        let increment = try decodePrefixedInteger(from: &cursor, prefixBits: 6, firstByte: first)
        guard increment > 0 else {
            throw QUICCodecError.malformed("QPACK Insert Count Increment must be non-zero")
        }
        return .insertCountIncrement(increment)
    }

}
