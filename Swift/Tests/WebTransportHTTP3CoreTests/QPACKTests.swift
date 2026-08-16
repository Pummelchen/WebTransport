import Foundation
import Testing
@testable import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func qpackStaticTableLooksUpExactAndNameEntries() {
    #expect(QPACKStaticTable.entries.count == 99)
    #expect(QPACKStaticTable.exactIndex(name: ":method", value: "CONNECT") == 15)
    #expect(QPACKStaticTable.exactIndex(name: ":scheme", value: "https") == 23)
    #expect(QPACKStaticTable.exactIndex(name: ":status", value: "200") == 25)
    #expect(QPACKStaticTable.exactIndex(name: "x-frame-options", value: "sameorigin") == 98)
    #expect(QPACKStaticTable.nameIndex(":authority") == 0)
    #expect(QPACKStaticTable.nameIndex("origin") == 90)
}

@Test
func qpackEncodesStaticIndexedAndLiteralFieldLines() throws {
    let fields = [
        try HTTPFieldLine(name: ":method", value: "CONNECT"),
        try HTTPFieldLine(name: ":authority", value: "example.com"),
        try HTTPFieldLine(name: ":protocol", value: "webtransport-h3"),
    ]
    let encoded = try QPACK.encodeFieldSection(fields)

    #expect(encoded.prefix(2) == Data([0x00, 0x00]))
    #expect(encoded.contains(0xcf))
    #expect(try QPACK.decodeFieldSection(encoded) == fields)
}

@Test
func webTransportConnectRequestHeadersFrameRoundTrips() throws {
    let frame = try WebTransportHTTP3Headers.connectRequestHeadersFrame(
        authority: "example.com",
        path: "/wt",
        origin: "https://example.com"
    )
    #expect(frame.type == HTTP3FrameType.headers)

    let fields = try QPACK.decodeHeadersFrame(frame)
    try WebTransportHTTP3Headers.validateConnectRequest(fields)
    #expect(
        fields == [
            try HTTPFieldLine(name: ":method", value: "CONNECT"),
            try HTTPFieldLine(name: ":scheme", value: "https"),
            try HTTPFieldLine(name: ":authority", value: "example.com"),
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: ":protocol", value: "webtransport-h3"),
            try HTTPFieldLine(name: "origin", value: "https://example.com"),
        ])
}

@Test
func webTransportResponseHeadersFrameRoundTrips() throws {
    let frame = try WebTransportHTTP3Headers.successfulResponseHeadersFrame()
    let fields = try QPACK.decodeHeadersFrame(frame)
    try WebTransportHTTP3Headers.validateSuccessfulResponse(fields)
    #expect(
        fields == [
            try HTTPFieldLine(name: ":status", value: "200")
        ])
}

@Test
func webTransportHeaderValidatorsRejectMalformedPseudoHeaders() throws {
    #expect(throws: Error.self) {
        _ = try WebTransportHTTP3Headers.connectRequest(authority: "", path: "/wt")
    }
    #expect(throws: Error.self) {
        _ = try WebTransportHTTP3Headers.connectRequest(authority: "example.com", path: "relative")
    }
    #expect(throws: Error.self) {
        try WebTransportHTTP3Headers.validateConnectRequest([
            try HTTPFieldLine(name: ":method", value: "GET"),
            try HTTPFieldLine(name: ":scheme", value: "https"),
            try HTTPFieldLine(name: ":authority", value: "example.com"),
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: ":protocol", value: "webtransport-h3"),
        ])
    }
    #expect(throws: Error.self) {
        try WebTransportHTTP3Headers.validateConnectRequest([
            try HTTPFieldLine(name: ":method", value: "CONNECT"),
            try HTTPFieldLine(name: ":scheme", value: "http"),
            try HTTPFieldLine(name: ":authority", value: "example.com"),
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: ":protocol", value: "webtransport-h3"),
        ])
    }
    #expect(throws: Error.self) {
        try WebTransportHTTP3Headers.validateConnectRequest([
            try HTTPFieldLine(name: ":method", value: "CONNECT"),
            try HTTPFieldLine(name: ":scheme", value: "https"),
            try HTTPFieldLine(name: ":authority", value: "example.com"),
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: ":protocol", value: "webtransport"),
        ])
    }
    #expect(throws: Error.self) {
        try WebTransportHTTP3Headers.validateConnectRequest([
            try HTTPFieldLine(name: "origin", value: "https://example.com"),
            try HTTPFieldLine(name: ":method", value: "CONNECT"),
        ])
    }
    #expect(throws: Error.self) {
        _ = try WebTransportHTTP3Headers.successfulResponse(status: 404)
    }
}

@Test
func qpackDecoderRejectsUnsupportedAndOversizedInputs() throws {
    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(Data([0x01, 0x00]))
    }
    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(Data([0x00, 0x80]))
    }
    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(Data([0x00, 0x00, 0xff]))
    }
    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(Data([0x00, 0x00, 0x27]))
    }
    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(
            try QPACK.encodeFieldSection([
                try HTTPFieldLine(name: ":path", value: String(repeating: "a", count: 12))
            ]),
            limits: QPACKDecoderLimits(maxFieldSectionBytes: 64, maxFieldLineBytes: 8, maxFieldLineCount: 8)
        )
    }
    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(
            try QPACK.encodeFieldSection([
                try HTTPFieldLine(name: ":path", value: "/"),
                try HTTPFieldLine(name: ":scheme", value: "https"),
            ]),
            limits: QPACKDecoderLimits(maxFieldSectionBytes: 64, maxFieldLineBytes: 64, maxFieldLineCount: 1)
        )
    }
}

@Test
func qpackHeadersFrameRejectsNonHeadersFrame() throws {
    #expect(throws: Error.self) {
        _ = try QPACK.decodeHeadersFrame(try HTTP3Frame(type: HTTP3FrameType.data, payload: Data()))
    }
}

@Test
func qpackHuffmanRoundTripsRFC7541Example() throws {
    let plain = Data("www.example.com".utf8)
    let encoded = QPACKHuffman.encode(plain)

    #expect(encoded == Data([0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]))
    #expect(try QPACKHuffman.decode(encoded) == plain)

    let fields = [
        try HTTPFieldLine(name: ":authority", value: "www.example.com"),
        try HTTPFieldLine(name: ":path", value: "/wt"),
    ]
    #expect(try QPACK.decodeFieldSection(try QPACK.encodeFieldSection(fields, huffman: true)) == fields)
}

@Test
func qpackHuffmanRejectsInvalidEOSAndPadding() throws {
    #expect(throws: Error.self) {
        _ = try QPACKHuffman.decode(Data([0xff, 0xff, 0xff, 0xff]))
    }
    #expect(throws: Error.self) {
        _ = try QPACKHuffman.decode(Data([0x00]))
    }
}

@Test
func qpackDynamicTableIndexesFieldsWithExplicitContext() throws {
    var table = try QPACKDynamicTable(capacity: 128)
    let dynamicField = try HTTPFieldLine(name: "origin", value: "https://example.com")
    try table.insert(dynamicField)

    let encoded = try QPACK.encodeFieldSection([dynamicField], dynamicTable: table)
    // The Required Insert Count goes on the wire wrapped, per RFC 9204 section
    // 4.5.1.1, not raw. A 128 byte capacity holds four entries, so the window is
    // eight and a count of one is sent as (1 % 8) + 1 = 2.
    #expect(encoded.prefix(2) == Data([0x02, 0x00]))
    #expect(encoded.dropFirst(2).first == 0x80)
    #expect(try QPACK.decodeFieldSection(encoded, dynamicTable: table) == [dynamicField])

    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(encoded)
    }
}

@Test
func qpackDecodesPostBaseIndexedAndNameReferences() throws {
    var table = try QPACKDynamicTable(capacity: 256)
    let first = try HTTPFieldLine(name: "origin", value: "https://one.example")
    let second = try HTTPFieldLine(name: "x-demo", value: "two")
    let third = try HTTPFieldLine(name: "x-demo", value: "three")
    try table.insert(first)
    try table.insert(second)
    try table.insert(third)

    // Leading byte is the wrapped Required Insert Count: a 256 byte capacity
    // holds eight entries, so three inserts are sent as (3 % 16) + 1 = 4.
    var fieldSection = Data([0x04, 0x81, 0x11, 0x00, 0x08])
    fieldSection.append(Data("override".utf8))

    #expect(
        try QPACK.decodeFieldSection(fieldSection, dynamicTable: table) == [
            third,
            try HTTPFieldLine(name: "x-demo", value: "override"),
        ])

    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(Data([0x01, 0x81]), dynamicTable: table)
    }
}

@Test
func qpackDynamicTableCapacityEvictsAndRejectsInvalidReferences() throws {
    var table = try QPACKDynamicTable(capacity: 47)
    let first = try HTTPFieldLine(name: "origin", value: "https://a")
    let second = try HTTPFieldLine(name: "origin", value: "https://b")
    try table.insert(first)
    try table.insert(second)

    #expect(table.entries == [second])
    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(Data([0x01, 0x00, 0x81]), dynamicTable: table)
    }
}

@Test
func qpackEncoderStreamInstructionsRoundTripAndPopulateDynamicTable() throws {
    let instructions: [QPACKEncoderStreamInstruction] = [
        .setDynamicTableCapacity(256),
        .insertWithNameReference(name: .staticTable(index: 1), value: "/wt"),
        .insertWithLiteralName(name: "origin", value: "https://example.com"),
        .duplicate(relativeIndex: 1),
        .insertWithNameReference(name: .dynamicTable(relativeIndex: 1), value: "https://again.example"),
    ]
    let encoded = try QPACK.encodeEncoderStreamInstructions(instructions, huffman: true)
    #expect(try QPACK.decodeEncoderStreamInstructions(encoded) == instructions)

    var table = try QPACKDynamicTable(capacity: 0, maximumCapacity: 512)
    let inserted = try QPACK.applyEncoderStream(encoded, to: &table)

    #expect(
        inserted == [
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: "origin", value: "https://example.com"),
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: "origin", value: "https://again.example"),
        ])
    #expect(table.capacity == 256)
    let mostRecent = try HTTPFieldLine(name: "origin", value: "https://again.example")
    #expect(table.entries.first == mostRecent)

    let fields = [
        try HTTPFieldLine(name: "origin", value: "https://again.example"),
        try HTTPFieldLine(name: ":path", value: "/wt"),
    ]
    let fieldSection = try QPACK.encodeFieldSection(fields, dynamicTable: table)
    #expect(try QPACK.decodeFieldSection(fieldSection, dynamicTable: table) == fields)
}

@Test
func qpackEncoderStreamRejectsInvalidDynamicInstructions() throws {
    var table = try QPACKDynamicTable(capacity: 0, maximumCapacity: 32)
    #expect(throws: Error.self) {
        _ = try QPACK.applyEncoderStream(
            try QPACK.encodeEncoderStreamInstructions([.setDynamicTableCapacity(64)]),
            to: &table
        )
    }

    table = try QPACKDynamicTable(capacity: 32)
    #expect(throws: Error.self) {
        _ = try QPACK.applyEncoderStream(
            try QPACK.encodeEncoderStreamInstructions([
                .insertWithNameReference(name: .dynamicTable(relativeIndex: 0), value: "x")
            ]),
            to: &table
        )
    }
    #expect(throws: Error.self) {
        _ = try QPACK.applyEncoderStream(
            try QPACK.encodeEncoderStreamInstructions([.duplicate(relativeIndex: 0)]),
            to: &table
        )
    }

    table = try QPACKDynamicTable(capacity: 32)
    #expect(throws: Error.self) {
        _ = try QPACK.applyEncoderStream(
            try QPACK.encodeEncoderStreamInstructions([
                .insertWithLiteralName(name: "origin", value: "https://too-large.example")
            ]),
            to: &table
        )
    }
}

@Test
func qpackDecoderStreamInstructionsRoundTripAndUpdateState() throws {
    let instructions: [QPACKDecoderStreamInstruction] = [
        .sectionAcknowledgement(streamID: 4),
        .streamCancellation(streamID: 8),
        .insertCountIncrement(3),
    ]
    let encoded = try QPACK.encodeDecoderStreamInstructions(instructions)
    #expect(try QPACK.decodeDecoderStreamInstructions(encoded) == instructions)

    var state = QPACKDecoderStreamState()
    for instruction in instructions {
        try state.apply(instruction, totalInsertCountSent: 3)
    }
    #expect(state.acknowledgedStreamIDs == [4])
    #expect(state.cancelledStreamIDs == [8])
    #expect(state.knownReceivedCount == 3)

    #expect(throws: Error.self) {
        try state.apply(.sectionAcknowledgement(streamID: 4), totalInsertCountSent: 3)
    }
    #expect(throws: Error.self) {
        try state.apply(.insertCountIncrement(1), totalInsertCountSent: 3)
    }
    #expect(throws: Error.self) {
        _ = try QPACK.decodeDecoderStreamInstructions(Data([0x00]))
    }
    #expect(throws: Error.self) {
        _ = try QPACK.encodeDecoderStreamInstruction(.insertCountIncrement(0))
    }
}

// MARK: - Required Insert Count encoding (RFC 9204 section 4.5.1.1)

/// The count is sent wrapped, not raw, so it cannot grow without bound as a
/// connection ages. Encoding it raw is self-consistent but disagrees with any
/// conforming peer as soon as a dynamic reference appears.
@Test
func requiredInsertCountIsWrappedAgainstTwiceTheTableSize() throws {
    // A 128 byte capacity holds four entries at the fixed 32 byte overhead, so
    // the wrap window is eight.
    let maxEntries = qpackMaxEntries(tableCapacity: 128)
    #expect(maxEntries == 4)

    #expect(try encodeRequiredInsertCount(0, maxEntries: maxEntries) == 0)
    #expect(try encodeRequiredInsertCount(1, maxEntries: maxEntries) == 2)
    #expect(try encodeRequiredInsertCount(7, maxEntries: maxEntries) == 8)
    // Eight is the window, so it wraps back to the bottom rather than growing.
    #expect(try encodeRequiredInsertCount(8, maxEntries: maxEntries) == 1)
    #expect(try encodeRequiredInsertCount(9, maxEntries: maxEntries) == 2)
}

@Test
func requiredInsertCountSurvivesAWrapWhenDecoded() throws {
    let maxEntries = qpackMaxEntries(tableCapacity: 128)
    // Every count the encoder could hold must come back intact given how many
    // entries it has actually inserted.
    for count in UInt64(1)...UInt64(20) {
        let encoded = try encodeRequiredInsertCount(count, maxEntries: maxEntries)
        let decoded = try decodeRequiredInsertCount(
            encoded,
            maxEntries: maxEntries,
            totalNumberOfInserts: count
        )
        #expect(decoded == count, "round trip failed for \(count)")
    }
}

@Test
func zeroMeansNoDynamicReferencesRegardlessOfCapacity() throws {
    #expect(try encodeRequiredInsertCount(0, maxEntries: 0) == 0)
    #expect(try decodeRequiredInsertCount(0, maxEntries: 0, totalNumberOfInserts: 0) == 0)
}

/// Without an advertised capacity a peer may not reference the dynamic table at
/// all, so a non-zero count is not representable and must be refused rather than
/// encoded into something a peer would misread.
@Test
func aDynamicReferenceWithoutAdvertisedCapacityIsRefused() throws {
    #expect(throws: (any Error).self) {
        try encodeRequiredInsertCount(1, maxEntries: 0)
    }
    #expect(throws: (any Error).self) {
        try decodeRequiredInsertCount(1, maxEntries: 0, totalNumberOfInserts: 5)
    }
}

@Test
func anEncodedCountBeyondTheWindowIsRejected() throws {
    let maxEntries = qpackMaxEntries(tableCapacity: 128)
    // The window is 2 * maxEntries; anything above it cannot have been produced
    // by a conforming encoder.
    #expect(throws: (any Error).self) {
        try decodeRequiredInsertCount(2 * maxEntries + 1, maxEntries: maxEntries, totalNumberOfInserts: 100)
    }
}

/// The shipped configuration advertises no table capacity, so field sections
/// must still round trip with a Required Insert Count of zero.
@Test
func fieldSectionsStillRoundTripWithNoDynamicTable() throws {
    let fields = [
        try HTTPFieldLine(name: ":method", value: "CONNECT"),
        try HTTPFieldLine(name: ":protocol", value: "webtransport-h3"),
    ]
    let encoded = try QPACK.encodeFieldSection(fields, dynamicTable: nil)
    let decoded = try QPACK.decodeFieldSection(encoded)
    #expect(decoded == fields)
    #expect(encoded.first == 0x00, "Required Insert Count must be zero with no dynamic table")
}
