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
        guard
            lowercasedName.utf8.allSatisfy({ byte in
                byte == 0x3a || byte == 0x2d || (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x7a)
            })
        else {
            throw QUICCodecError.malformed("HTTP field name contains invalid bytes")
        }
        // RFC 9110 section 5.5: a field value is `field-content`, so every byte
        // must be visible, SP or HTAB; the other C0 controls and DEL are not value
        // bytes and RFC 9114 section 4.1.2 makes a field section carrying one
        // malformed. CR, LF and NUL are the bytes that turn a value into a second
        // field, and every one of them is valid UTF-8, so the decoder's UTF-8 check
        // alone let them through. Bytes at or above 0x80 are `obs-text` and legal.
        guard
            value.utf8.allSatisfy({ byte in
                byte == 0x09 || byte == 0x20 || (byte >= 0x21 && byte != 0x7f)
            })
        else {
            throw QUICCodecError.malformed("HTTP field value contains a forbidden byte")
        }
        self.name = name
        self.value = value
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

