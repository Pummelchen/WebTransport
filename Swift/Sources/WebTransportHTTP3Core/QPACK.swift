import Foundation
import WebTransportQUICCore

public struct HTTPFieldLine: Equatable, Sendable {
    public var name: String
    public var value: String

    public init(name: String, value: String) throws {
        let lowercasedName = name.lowercased()
        guard !lowercasedName.isEmpty else {
            throw QUICCodecError.malformed("HTTP field name must not be empty")
        }
        guard lowercasedName == name else {
            throw QUICCodecError.malformed("HTTP field name must be lowercase")
        }
        guard lowercasedName.utf8.allSatisfy({ byte in
            byte == 0x3a || byte == 0x2d || (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x7a)
        }) else {
            throw QUICCodecError.malformed("HTTP field name contains invalid bytes")
        }
        self.name = name
        self.value = value
    }
}

public struct QPACKStaticTableEntry: Equatable, Sendable {
    public var index: UInt64
    public var name: String
    public var value: String
}

public enum QPACKStaticTable {
    public static let entries: [QPACKStaticTableEntry] = [
        QPACKStaticTableEntry(index: 0, name: ":authority", value: ""),
        QPACKStaticTableEntry(index: 1, name: ":path", value: "/"),
        QPACKStaticTableEntry(index: 15, name: ":method", value: "CONNECT"),
        QPACKStaticTableEntry(index: 17, name: ":method", value: "GET"),
        QPACKStaticTableEntry(index: 20, name: ":method", value: "POST"),
        QPACKStaticTableEntry(index: 22, name: ":scheme", value: "http"),
        QPACKStaticTableEntry(index: 23, name: ":scheme", value: "https"),
        QPACKStaticTableEntry(index: 25, name: ":status", value: "200"),
        QPACKStaticTableEntry(index: 27, name: ":status", value: "404"),
        QPACKStaticTableEntry(index: 28, name: ":status", value: "503")
    ]

    public static func entry(index: UInt64) -> QPACKStaticTableEntry? {
        entries.first { $0.index == index }
    }

    public static func exactIndex(name: String, value: String) -> UInt64? {
        entries.first { $0.name == name && $0.value == value }?.index
    }

    public static func nameIndex(_ name: String) -> UInt64? {
        entries.first { $0.name == name }?.index
    }
}

public struct QPACKDecoderLimits: Equatable, Sendable {
    public var maxFieldSectionBytes: Int
    public var maxFieldLineBytes: Int
    public var maxFieldLineCount: Int

    public init(
        maxFieldSectionBytes: Int = 16_384,
        maxFieldLineBytes: Int = 8_192,
        maxFieldLineCount: Int = 128
    ) throws {
        guard maxFieldSectionBytes > 0, maxFieldLineBytes > 0, maxFieldLineCount > 0 else {
            throw QUICCodecError.valueOutOfRange("QPACK decoder limits must be positive")
        }
        self.init(
            uncheckedMaxFieldSectionBytes: maxFieldSectionBytes,
            maxFieldLineBytes: maxFieldLineBytes,
            maxFieldLineCount: maxFieldLineCount
        )
    }

    public static let `default` = QPACKDecoderLimits(
        uncheckedMaxFieldSectionBytes: 16_384,
        maxFieldLineBytes: 8_192,
        maxFieldLineCount: 128
    )

    private init(
        uncheckedMaxFieldSectionBytes maxFieldSectionBytes: Int,
        maxFieldLineBytes: Int,
        maxFieldLineCount: Int
    ) {
        self.maxFieldSectionBytes = maxFieldSectionBytes
        self.maxFieldLineBytes = maxFieldLineBytes
        self.maxFieldLineCount = maxFieldLineCount
    }
}

public struct QPACKDynamicTable: Equatable, Sendable {
    public private(set) var entries: [HTTPFieldLine]
    public private(set) var capacity: Int
    public private(set) var maximumCapacity: Int
    public private(set) var byteSize: Int
    public private(set) var insertedCount: UInt64

    public init(capacity: Int = 0, maximumCapacity: Int? = nil) throws {
        let maximumCapacity = maximumCapacity ?? capacity
        guard capacity >= 0, maximumCapacity >= 0 else {
            throw QUICCodecError.valueOutOfRange("QPACK dynamic table capacity must not be negative")
        }
        guard capacity <= maximumCapacity else {
            throw QUICCodecError.valueOutOfRange("QPACK dynamic table capacity exceeds maximum capacity")
        }
        self.entries = []
        self.capacity = capacity
        self.maximumCapacity = maximumCapacity
        self.byteSize = 0
        self.insertedCount = 0
    }

    public mutating func setCapacity(_ capacity: Int) throws {
        guard capacity >= 0 else {
            throw QUICCodecError.valueOutOfRange("QPACK dynamic table capacity must not be negative")
        }
        guard capacity <= maximumCapacity else {
            throw QUICCodecError.valueOutOfRange("QPACK dynamic table capacity exceeds peer maximum")
        }
        self.capacity = capacity
        evictToCapacity()
    }

    public mutating func insert(_ field: HTTPFieldLine) throws {
        let entrySize = Self.entrySize(field)
        guard entrySize <= capacity else {
            throw QUICCodecError.valueOutOfRange("QPACK dynamic table entry exceeds current capacity")
        }

        entries.insert(field, at: 0)
        byteSize += entrySize
        insertedCount += 1
        evictToCapacity()
    }

    public func relativeEntry(index: UInt64) throws -> HTTPFieldLine {
        guard index <= UInt64(Int.max), Int(index) < entries.count else {
            throw QUICCodecError.malformed("QPACK dynamic table relative index is invalid")
        }
        return entries[Int(index)]
    }

    public func fieldSectionRelativeEntry(
        index: UInt64,
        base: UInt64,
        requiredInsertCount: UInt64
    ) throws -> HTTPFieldLine {
        guard base > index else {
            throw QUICCodecError.malformed("QPACK dynamic table relative index is before the table")
        }
        let absoluteIndex = base - index - 1
        return try entry(absoluteIndex: absoluteIndex, requiredInsertCount: requiredInsertCount)
    }

    public func fieldSectionPostBaseEntry(
        index: UInt64,
        base: UInt64,
        requiredInsertCount: UInt64
    ) throws -> HTTPFieldLine {
        let (absoluteIndex, overflow) = base.addingReportingOverflow(index)
        guard !overflow else {
            throw QUICCodecError.malformed("QPACK dynamic table post-Base index overflow")
        }
        return try entry(absoluteIndex: absoluteIndex, requiredInsertCount: requiredInsertCount)
    }

    public func relativeIndex(name: String, value: String) -> UInt64? {
        guard let index = entries.firstIndex(where: { $0.name == name && $0.value == value }) else {
            return nil
        }
        return UInt64(index)
    }

    public mutating func apply(_ instruction: QPACKEncoderStreamInstruction) throws -> HTTPFieldLine? {
        switch instruction {
        case .setDynamicTableCapacity(let capacity):
            try setCapacity(capacity)
            return nil
        case .insertWithNameReference(let reference, let value):
            let name = try name(for: reference)
            let field = try HTTPFieldLine(name: name, value: value)
            try insert(field)
            return field
        case .insertWithLiteralName(let name, let value):
            let field = try HTTPFieldLine(name: name, value: value)
            try insert(field)
            return field
        case .duplicate(let relativeIndex):
            let field = try relativeEntry(index: relativeIndex)
            try insert(field)
            return field
        }
    }

    private func name(for reference: QPACKNameReference) throws -> String {
        switch reference {
        case .staticTable(let index):
            guard let entry = QPACKStaticTable.entry(index: index) else {
                throw QUICCodecError.malformed("QPACK static table name index is unknown")
            }
            return entry.name
        case .dynamicTable(let relativeIndex):
            return try relativeEntry(index: relativeIndex).name
        }
    }

    public func relativeNameIndex(_ name: String) -> UInt64? {
        guard let index = entries.firstIndex(where: { $0.name == name }) else {
            return nil
        }
        return UInt64(index)
    }

    private func entry(absoluteIndex: UInt64, requiredInsertCount: UInt64) throws -> HTTPFieldLine {
        guard absoluteIndex < requiredInsertCount else {
            throw QUICCodecError.malformed("QPACK dynamic reference exceeds Required Insert Count")
        }
        guard insertedCount > absoluteIndex else {
            throw QUICCodecError.malformed("QPACK dynamic reference has not been inserted")
        }
        let newestAbsoluteIndex = insertedCount - 1
        guard newestAbsoluteIndex >= absoluteIndex else {
            throw QUICCodecError.malformed("QPACK dynamic reference is invalid")
        }
        let relativeToNewest = newestAbsoluteIndex - absoluteIndex
        guard relativeToNewest <= UInt64(Int.max), Int(relativeToNewest) < entries.count else {
            throw QUICCodecError.malformed("QPACK dynamic reference has been evicted")
        }
        return entries[Int(relativeToNewest)]
    }

    private mutating func evictToCapacity() {
        while byteSize > capacity, let last = entries.last {
            byteSize -= Self.entrySize(last)
            entries.removeLast()
        }
    }

    private static func entrySize(_ field: HTTPFieldLine) -> Int {
        field.name.utf8.count + field.value.utf8.count + 32
    }
}

public enum QPACKNameReference: Equatable, Sendable {
    case staticTable(index: UInt64)
    case dynamicTable(relativeIndex: UInt64)
}

public enum QPACKEncoderStreamInstruction: Equatable, Sendable {
    case setDynamicTableCapacity(Int)
    case insertWithNameReference(name: QPACKNameReference, value: String)
    case insertWithLiteralName(name: String, value: String)
    case duplicate(relativeIndex: UInt64)
}

public enum QPACKDecoderStreamInstruction: Equatable, Sendable {
    case sectionAcknowledgement(streamID: UInt64)
    case streamCancellation(streamID: UInt64)
    case insertCountIncrement(UInt64)
}

public struct QPACKDecoderStreamState: Equatable, Sendable {
    public private(set) var knownReceivedCount: UInt64
    public private(set) var acknowledgedStreamIDs: Set<UInt64>
    public private(set) var cancelledStreamIDs: Set<UInt64>

    public init() {
        self.knownReceivedCount = 0
        self.acknowledgedStreamIDs = []
        self.cancelledStreamIDs = []
    }

    public mutating func apply(
        _ instruction: QPACKDecoderStreamInstruction,
        totalInsertCountSent: UInt64
    ) throws {
        switch instruction {
        case .sectionAcknowledgement(let streamID):
            guard acknowledgedStreamIDs.insert(streamID).inserted else {
                throw QUICCodecError.malformed("duplicate QPACK section acknowledgement")
            }
        case .streamCancellation(let streamID):
            cancelledStreamIDs.insert(streamID)
        case .insertCountIncrement(let increment):
            guard increment > 0 else {
                throw QUICCodecError.malformed("QPACK Insert Count Increment must be non-zero")
            }
            let (newCount, overflow) = knownReceivedCount.addingReportingOverflow(increment)
            guard !overflow, newCount <= totalInsertCountSent else {
                throw QUICCodecError.malformed("QPACK Insert Count Increment exceeds sent insert count")
            }
            knownReceivedCount = newCount
        }
    }
}

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
        var output = Data()
        output.append(try encodePrefixedInteger(requiredInsertCount, prefixBits: 8, firstBytePrefix: 0x00))
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
        let requiredInsertCount = try decodePrefixedInteger(from: &cursor, prefixBits: 8)
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

        if (first & 0x40) != 0 {
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

        if (first & 0xf0) == 0x10 {
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

        if (first & 0xf0) == 0x00 {
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

        if (first & 0x20) != 0 {
            let name = try decodeStringLiteral(from: &cursor, prefixBits: 3, firstByte: first)
            let value = try decodeStringLiteral(from: &cursor, prefixBits: 7)
            return try HTTPFieldLine(name: name, value: value)
        }

        throw QUICCodecError.malformed("unsupported QPACK field-line representation")
    }

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

    private static func decodeEncoderStreamInstruction(
        from cursor: inout QUICByteCursor
    ) throws -> QPACKEncoderStreamInstruction {
        let first = try cursor.readUInt8()
        if (first & 0x80) != 0 {
            let index = try decodePrefixedInteger(from: &cursor, prefixBits: 6, firstByte: first)
            let reference: QPACKNameReference = (first & 0x40) != 0
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

    private static func decodeDecoderStreamInstruction(
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

private func encodeStringLiteral(
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

private func decodeStringLiteral(
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

private func checkedLength(_ value: UInt64) throws -> Int {
    guard value <= UInt64(Int.max) else {
        throw QUICCodecError.valueOutOfRange("QPACK length exceeds Int.max")
    }
    return Int(value)
}

private func encodePrefixedInteger(
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

private func decodePrefixedInteger(
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
