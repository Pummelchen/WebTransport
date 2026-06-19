import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func qpackStaticTableLooksUpExactAndNameEntries() {
    #expect(QPACKStaticTable.exactIndex(name: ":method", value: "CONNECT") == 15)
    #expect(QPACKStaticTable.exactIndex(name: ":scheme", value: "https") == 23)
    #expect(QPACKStaticTable.exactIndex(name: ":status", value: "200") == 25)
    #expect(QPACKStaticTable.nameIndex(":authority") == 0)
    #expect(QPACKStaticTable.nameIndex("origin") == nil)
}

@Test
func qpackEncodesStaticIndexedAndLiteralFieldLines() throws {
    let fields = [
        try HTTPFieldLine(name: ":method", value: "CONNECT"),
        try HTTPFieldLine(name: ":authority", value: "example.com"),
        try HTTPFieldLine(name: ":protocol", value: "webtransport-h3")
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
    #expect(fields == [
        try HTTPFieldLine(name: ":method", value: "CONNECT"),
        try HTTPFieldLine(name: ":scheme", value: "https"),
        try HTTPFieldLine(name: ":authority", value: "example.com"),
        try HTTPFieldLine(name: ":path", value: "/wt"),
        try HTTPFieldLine(name: ":protocol", value: "webtransport-h3"),
        try HTTPFieldLine(name: "origin", value: "https://example.com")
    ])
}

@Test
func webTransportResponseHeadersFrameRoundTrips() throws {
    let frame = try WebTransportHTTP3Headers.successfulResponseHeadersFrame()
    let fields = try QPACK.decodeHeadersFrame(frame)
    try WebTransportHTTP3Headers.validateSuccessfulResponse(fields)
    #expect(fields == [
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
            try HTTPFieldLine(name: ":protocol", value: "webtransport-h3")
        ])
    }
    #expect(throws: Error.self) {
        try WebTransportHTTP3Headers.validateConnectRequest([
            try HTTPFieldLine(name: ":method", value: "CONNECT"),
            try HTTPFieldLine(name: ":scheme", value: "http"),
            try HTTPFieldLine(name: ":authority", value: "example.com"),
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: ":protocol", value: "webtransport-h3")
        ])
    }
    #expect(throws: Error.self) {
        try WebTransportHTTP3Headers.validateConnectRequest([
            try HTTPFieldLine(name: ":method", value: "CONNECT"),
            try HTTPFieldLine(name: ":scheme", value: "https"),
            try HTTPFieldLine(name: ":authority", value: "example.com"),
            try HTTPFieldLine(name: ":path", value: "/wt"),
            try HTTPFieldLine(name: ":protocol", value: "webtransport")
        ])
    }
    #expect(throws: Error.self) {
        try WebTransportHTTP3Headers.validateConnectRequest([
            try HTTPFieldLine(name: "origin", value: "https://example.com"),
            try HTTPFieldLine(name: ":method", value: "CONNECT")
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
                try HTTPFieldLine(name: ":scheme", value: "https")
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
        try HTTPFieldLine(name: ":path", value: "/wt")
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
    #expect(encoded.prefix(2) == Data([0x01, 0x00]))
    #expect(encoded.dropFirst(2).first == 0x80)
    #expect(try QPACK.decodeFieldSection(encoded, dynamicTable: table) == [dynamicField])

    #expect(throws: Error.self) {
        _ = try QPACK.decodeFieldSection(encoded)
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
