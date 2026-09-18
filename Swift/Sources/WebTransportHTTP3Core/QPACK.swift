import Foundation
import WebTransportQUICCore

public enum QPACK {
    public static func encodeFieldSection(
        _ fields: [HTTPFieldLine],
        huffman: Bool = false
    ) throws -> Data {
        try encodeFieldSection(fields, dynamicTable: nil, huffman: huffman)
    }

    public static func encodeFieldSection(
        _ fields: [HTTPFieldLine],
        dynamicTable: QPACKDynamicTable?,
        huffman: Bool = false
    ) throws -> Data {
        let requiredInsertCount = dynamicTable?.insertedCount ?? 0
        let encodedInsertCount = try encodeRequiredInsertCount(
            requiredInsertCount,
            maxEntries: qpackMaxEntries(tableCapacity: dynamicTable?.maximumCapacity ?? 0)
        )
        var output = Data()
        output.append(try encodePrefixedInteger(encodedInsertCount, prefixBits: 8, firstBytePrefix: 0x00))
        output.append(0x00)
        for field in fields {
            output.append(try encodeFieldLine(field, dynamicTable: dynamicTable, huffman: huffman))
        }
        return output
    }

    public static func decodeFieldSection(
        _ data: Data,
        limits: QPACKDecoderLimits = .default
    ) throws -> [HTTPFieldLine] {
        try decodeFieldSection(data, dynamicTable: nil, limits: limits)
    }

    public static func decodeFieldSection(
        _ data: Data,
        dynamicTable: QPACKDynamicTable?,
        limits: QPACKDecoderLimits = .default
    ) throws -> [HTTPFieldLine] {
        guard data.count <= limits.maxFieldSectionBytes else {
            throw QUICCodecError.valueOutOfRange("QPACK field section exceeds configured limit")
        }

        var cursor = QUICByteCursor(data)
        let encodedInsertCount = try decodePrefixedInteger(from: &cursor, prefixBits: 8)
        let requiredInsertCount = try decodeRequiredInsertCount(
            encodedInsertCount,
            maxEntries: qpackMaxEntries(tableCapacity: dynamicTable?.maximumCapacity ?? 0),
            totalNumberOfInserts: dynamicTable?.insertedCount ?? 0
        )
        let baseByte = try cursor.readUInt8()
        let deltaBase = try decodePrefixedInteger(from: &cursor, prefixBits: 7, firstByte: baseByte)
        let baseSign = (baseByte & 0x80) != 0

        guard requiredInsertCount == 0 || dynamicTable != nil else {
            throw QUICCodecError.malformed("dynamic QPACK references require a dynamic table context")
        }
        if requiredInsertCount > 0 {
            guard let dynamicTable, requiredInsertCount <= dynamicTable.insertedCount else {
                throw QUICCodecError.malformed("QPACK Required Insert Count exceeds dynamic table state")
            }
            if baseSign {
                guard requiredInsertCount > deltaBase else {
                    throw QUICCodecError.malformed("QPACK Base is negative")
                }
            }
        } else if baseSign || deltaBase != 0 {
            throw QUICCodecError.malformed("QPACK Base must be zero when there are no dynamic references")
        }
        let base = try fieldSectionBase(
            requiredInsertCount: requiredInsertCount,
            deltaBase: deltaBase,
            sign: baseSign
        )

        var fields: [HTTPFieldLine] = []
        while !cursor.isAtEnd {
            guard fields.count < limits.maxFieldLineCount else {
                throw QUICCodecError.valueOutOfRange("QPACK field line count exceeds configured limit")
            }
            let field = try decodeFieldLine(
                from: &cursor,
                dynamicTable: dynamicTable,
                base: base,
                requiredInsertCount: requiredInsertCount
            )
            guard field.name.utf8.count + field.value.utf8.count <= limits.maxFieldLineBytes else {
                throw QUICCodecError.valueOutOfRange("QPACK field line exceeds configured limit")
            }
            fields.append(field)
        }
        return fields
    }

    public static func headersFrame(fields: [HTTPFieldLine]) throws -> HTTP3Frame {
        try HTTP3Frame(type: HTTP3FrameType.headers, payload: encodeFieldSection(fields))
    }

    public static func decodeHeadersFrame(
        _ frame: HTTP3Frame,
        limits: QPACKDecoderLimits = .default
    ) throws -> [HTTPFieldLine] {
        guard frame.type == HTTP3FrameType.headers else {
            throw QUICCodecError.malformed("QPACK HEADERS decoder received non-HEADERS frame")
        }
        return try decodeFieldSection(frame.payload, limits: limits)
    }

    static func encodeFieldLine(
        _ field: HTTPFieldLine,
        dynamicTable: QPACKDynamicTable?,
        huffman: Bool
    ) throws -> Data {
        if let dynamicIndex = dynamicTable?.relativeIndex(name: field.name, value: field.value) {
            return try encodePrefixedInteger(dynamicIndex, prefixBits: 6, firstBytePrefix: 0x80)
        }

        if let index = QPACKStaticTable.exactIndex(name: field.name, value: field.value) {
            return try encodePrefixedInteger(index, prefixBits: 6, firstBytePrefix: 0xc0)
        }

        let valueBytes = Data(field.value.utf8)
        if let nameIndex = QPACKStaticTable.nameIndex(field.name) {
            var output = try encodePrefixedInteger(nameIndex, prefixBits: 4, firstBytePrefix: 0x50)
            output.append(try encodeStringLiteral(valueBytes, prefixBits: 7, firstBytePrefix: 0x00, huffman: huffman))
            return output
        }
        if let dynamicNameIndex = dynamicTable?.relativeNameIndex(field.name) {
            var output = try encodePrefixedInteger(dynamicNameIndex, prefixBits: 4, firstBytePrefix: 0x40)
            output.append(try encodeStringLiteral(valueBytes, prefixBits: 7, firstBytePrefix: 0x00, huffman: huffman))
            return output
        }

        var output = try encodeStringLiteral(Data(field.name.utf8), prefixBits: 3, firstBytePrefix: 0x20, huffman: huffman)
        output.append(try encodeStringLiteral(valueBytes, prefixBits: 7, firstBytePrefix: 0x00, huffman: huffman))
        return output
    }

    static func decodeFieldLine(
        from cursor: inout QUICByteCursor,
        dynamicTable: QPACKDynamicTable?,
        base: UInt64,
        requiredInsertCount: UInt64
    ) throws -> HTTPFieldLine {
        let first = try cursor.readUInt8()
        if (first & 0x80) != 0 {
            return try decodeIndexedFieldLine(
                first: first,
                from: &cursor,
                dynamicTable: dynamicTable,
                base: base,
                requiredInsertCount: requiredInsertCount
            )
        }
        if (first & 0x40) != 0 {
            return try decodeFieldLineWithNameReference(
                first: first,
                from: &cursor,
                dynamicTable: dynamicTable,
                base: base,
                requiredInsertCount: requiredInsertCount
            )
        }
        if (first & 0xf0) == 0x10 {
            return try decodePostBaseIndexedFieldLine(
                first: first,
                from: &cursor,
                dynamicTable: dynamicTable,
                base: base,
                requiredInsertCount: requiredInsertCount
            )
        }
        if (first & 0xf0) == 0x00 {
            return try decodePostBaseNameReferenceFieldLine(
                first: first,
                from: &cursor,
                dynamicTable: dynamicTable,
                base: base,
                requiredInsertCount: requiredInsertCount
            )
        }
        if (first & 0x20) != 0 {
            let name = try decodeStringLiteral(from: &cursor, prefixBits: 3, firstByte: first)
            let value = try decodeStringLiteral(from: &cursor, prefixBits: 7)
            return try HTTPFieldLine(name: name, value: value)
        }
        throw QUICCodecError.malformed("unsupported QPACK field-line representation")
    }

}

/// `1xxxxxxx`: an indexed field line, static or dynamic.
private func decodeIndexedFieldLine(
    first: UInt8,
    from cursor: inout QUICByteCursor,
    dynamicTable: QPACKDynamicTable?,
    base: UInt64,
    requiredInsertCount: UInt64
) throws -> HTTPFieldLine {
    let index = try decodePrefixedInteger(from: &cursor, prefixBits: 6, firstByte: first)
    let isStatic = (first & 0x40) != 0
    if !isStatic {
        guard let dynamicTable else {
            throw QUICCodecError.malformed("dynamic QPACK indexed fields require a dynamic table context")
        }
        return try dynamicTable.fieldSectionRelativeEntry(
            index: index,
            base: base,
            requiredInsertCount: requiredInsertCount
        )
    }
    guard let entry = QPACKStaticTable.entry(index: index) else {
        throw QUICCodecError.malformed("QPACK static table index is unknown")
    }
    return try HTTPFieldLine(name: entry.name, value: entry.value)
}

/// `01xxxxxx`: a literal field line whose name is a static or dynamic reference.
private func decodeFieldLineWithNameReference(
    first: UInt8,
    from cursor: inout QUICByteCursor,
    dynamicTable: QPACKDynamicTable?,
    base: UInt64,
    requiredInsertCount: UInt64
) throws -> HTTPFieldLine {
    let nameIndex = try decodePrefixedInteger(from: &cursor, prefixBits: 4, firstByte: first)
    let isStatic = (first & 0x10) != 0
    let name: String
    if isStatic {
        guard let entry = QPACKStaticTable.entry(index: nameIndex) else {
            throw QUICCodecError.malformed("QPACK static table name index is unknown")
        }
        name = entry.name
    } else {
        guard let dynamicTable else {
            throw QUICCodecError.malformed("dynamic QPACK name references require a dynamic table context")
        }
        name = try dynamicTable.fieldSectionRelativeEntry(
            index: nameIndex,
            base: base,
            requiredInsertCount: requiredInsertCount
        ).name
    }
    let value = try decodeStringLiteral(from: &cursor, prefixBits: 7)
    return try HTTPFieldLine(name: name, value: value)
}

/// `0001xxxx`: an indexed field line from the post-Base region.
private func decodePostBaseIndexedFieldLine(
    first: UInt8,
    from cursor: inout QUICByteCursor,
    dynamicTable: QPACKDynamicTable?,
    base: UInt64,
    requiredInsertCount: UInt64
) throws -> HTTPFieldLine {
    guard let dynamicTable else {
        throw QUICCodecError.malformed("dynamic QPACK post-Base indexed fields require a dynamic table context")
    }
    let index = try decodePrefixedInteger(from: &cursor, prefixBits: 4, firstByte: first)
    return try dynamicTable.fieldSectionPostBaseEntry(
        index: index,
        base: base,
        requiredInsertCount: requiredInsertCount
    )
}

/// `0000xxxx`: a literal field line whose name is a post-Base reference.
private func decodePostBaseNameReferenceFieldLine(
    first: UInt8,
    from cursor: inout QUICByteCursor,
    dynamicTable: QPACKDynamicTable?,
    base: UInt64,
    requiredInsertCount: UInt64
) throws -> HTTPFieldLine {
    guard let dynamicTable else {
        throw QUICCodecError.malformed("dynamic QPACK post-Base name references require a dynamic table context")
    }
    let nameIndex = try decodePrefixedInteger(from: &cursor, prefixBits: 3, firstByte: first)
    let name = try dynamicTable.fieldSectionPostBaseEntry(
        index: nameIndex,
        base: base,
        requiredInsertCount: requiredInsertCount
    ).name
    let value = try decodeStringLiteral(from: &cursor, prefixBits: 7)
    return try HTTPFieldLine(name: name, value: value)
}

private func fieldSectionBase(
    requiredInsertCount: UInt64,
    deltaBase: UInt64,
    sign: Bool
) throws -> UInt64 {
    if sign {
        guard requiredInsertCount > deltaBase else {
            throw QUICCodecError.malformed("QPACK Base is negative")
        }
        return requiredInsertCount - deltaBase - 1
    }
    let (base, overflow) = requiredInsertCount.addingReportingOverflow(deltaBase)
    guard !overflow else {
        throw QUICCodecError.valueOutOfRange("QPACK Base overflows UInt64")
    }
    return base
}

// MARK: - Required Insert Count encoding (RFC 9204 section 4.5.1.1)

/// How many entries the peer's advertised table capacity can hold.
///
/// RFC 9204 section 3.2.2 fixes the per-entry overhead at 32 bytes, so this is
/// `floor(capacity / 32)`. It is the modulus the Required Insert Count is
/// wrapped against, which is why a field section cannot be encoded or decoded
/// without knowing the capacity that was negotiated.
func qpackMaxEntries(tableCapacity: Int) -> UInt64 {
    guard tableCapacity > 0 else {
        return 0
    }
    return UInt64(tableCapacity / 32)
}

/// Wraps a Required Insert Count for the wire.
///
/// The count is not sent directly: it is sent modulo twice the table size so the
/// field never grows with the connection, and offset by one so that zero can
/// mean "no dynamic references" unambiguously.
func encodeRequiredInsertCount(_ requiredInsertCount: UInt64, maxEntries: UInt64) throws -> UInt64 {
    guard requiredInsertCount > 0 else {
        return 0
    }
    guard maxEntries > 0 else {
        // No capacity was advertised, so the peer may not reference the dynamic
        // table at all and no non-zero count is representable.
        throw QUICCodecError.malformed("QPACK dynamic reference without an advertised table capacity")
    }
    return (requiredInsertCount % (2 * maxEntries)) + 1
}

/// Recovers the Required Insert Count from its wrapped form.
///
/// Reconstruction needs how many entries the encoder has inserted so far,
/// because the wrapped value only identifies the count within one window and the
/// insert count says which window that is.
func decodeRequiredInsertCount(
    _ encoded: UInt64,
    maxEntries: UInt64,
    totalNumberOfInserts: UInt64
) throws -> UInt64 {
    guard encoded > 0 else {
        return 0
    }
    guard maxEntries > 0 else {
        throw QUICCodecError.malformed("QPACK dynamic reference without an advertised table capacity")
    }
    let fullRange = 2 * maxEntries
    guard encoded <= fullRange else {
        throw QUICCodecError.malformed("QPACK encoded Required Insert Count exceeds the table window")
    }
    let maxValue = totalNumberOfInserts + maxEntries
    let maxWrapped = (maxValue / fullRange) * fullRange
    var requiredInsertCount = maxWrapped + encoded - 1
    if requiredInsertCount > maxValue {
        guard requiredInsertCount > fullRange else {
            throw QUICCodecError.malformed("QPACK Required Insert Count is not representable")
        }
        requiredInsertCount -= fullRange
    }
    guard requiredInsertCount > 0 else {
        throw QUICCodecError.malformed("QPACK Required Insert Count decoded to zero")
    }
    return requiredInsertCount
}

extension QPACK {
    public static func encodeEncoderStreamInstruction(
        _ instruction: QPACKEncoderStreamInstruction,
        huffman: Bool = false
    ) throws -> Data {
        switch instruction {
        case .setDynamicTableCapacity(let capacity):
            guard capacity >= 0 else {
                throw QUICCodecError.valueOutOfRange("QPACK dynamic table capacity must not be negative")
            }
            return try encodePrefixedInteger(UInt64(capacity), prefixBits: 5, firstBytePrefix: 0x20)
        case .insertWithNameReference(let reference, let value):
            let prefix: UInt8
            let index: UInt64
            switch reference {
            case .staticTable(let staticIndex):
                prefix = 0xc0
                index = staticIndex
            case .dynamicTable(let relativeIndex):
                prefix = 0x80
                index = relativeIndex
            }
            var output = try encodePrefixedInteger(index, prefixBits: 6, firstBytePrefix: prefix)
            output.append(try encodeStringLiteral(Data(value.utf8), prefixBits: 7, firstBytePrefix: 0x00, huffman: huffman))
            return output
        case .insertWithLiteralName(let name, let value):
            var output = try encodeStringLiteral(Data(name.utf8), prefixBits: 5, firstBytePrefix: 0x40, huffman: huffman)
            output.append(try encodeStringLiteral(Data(value.utf8), prefixBits: 7, firstBytePrefix: 0x00, huffman: huffman))
            return output
        case .duplicate(let relativeIndex):
            return try encodePrefixedInteger(relativeIndex, prefixBits: 5, firstBytePrefix: 0x00)
        }
    }

    public static func encodeDecoderStreamInstruction(_ instruction: QPACKDecoderStreamInstruction) throws -> Data {
        switch instruction {
        case .sectionAcknowledgement(let streamID):
            return try encodePrefixedInteger(streamID, prefixBits: 7, firstBytePrefix: 0x80)
        case .streamCancellation(let streamID):
            return try encodePrefixedInteger(streamID, prefixBits: 6, firstBytePrefix: 0x40)
        case .insertCountIncrement(let increment):
            guard increment > 0 else {
                throw QUICCodecError.malformed("QPACK Insert Count Increment must be non-zero")
            }
            return try encodePrefixedInteger(increment, prefixBits: 6, firstBytePrefix: 0x00)
        }
    }

}
