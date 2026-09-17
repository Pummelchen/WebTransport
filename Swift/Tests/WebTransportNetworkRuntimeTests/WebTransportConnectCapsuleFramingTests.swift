import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore
@testable import WebTransportNetworkRuntime

/// WT-249: CONNECT-stream capsules travel in HTTP/3 DATA frames.
///
/// RFC 9297 section 3.1 makes the HTTP/3 data stream "all bytes sent in DATA
/// frames", section 3.2 defines the Capsule Protocol as the contents of that
/// stream, and RFC 9114 section 4.4 permits only DATA frames after CONNECT.
/// Writing the capsule TLV straight to the stream therefore puts a frame of an
/// unknown type on the wire, which RFC 9114 section 9 makes the peer ignore: the
/// capsule is dropped, not rejected. These tests pin the framed form and the
/// tolerance for the historical raw form (skipped as an unknown frame) that kept
/// the defect invisible to the interop suite.

private func connectCapsule(type: UInt64, payload: Data) throws -> Data {
    var capsule = try QUICVarInt.encode(type)
    capsule.append(try QUICVarInt.encode(UInt64(payload.count)))
    capsule.append(payload)
    return capsule
}

private func dataFrame(_ payload: Data) throws -> Data {
    try HTTP3Frame(type: HTTP3FrameType.data, payload: payload).encode()
}

/// The close capsule a session writes is the payload of a DATA frame, so a
/// conformant peer's frame decoder hands it on instead of discarding it.
@Test
func connectStreamCapsulesAreWrappedInDataFrames() throws {
    let capsule = try connectCapsule(type: 0x2843, payload: Data([0x00, 0x00, 0x00, 0x09, 0x5f]))
    let framed = try InteroperableCONNECTCapsuleFraming.wrap(capsule)

    let (frame, consumed) = try HTTP3Frame.decodePrefix(framed)
    #expect(frame.type == HTTP3FrameType.data, "a capsule must be a DATA frame payload, not a bare TLV")
    #expect(frame.payload == capsule)
    #expect(consumed == framed.count)
    // The raw form the runtime used to write is a frame of type 0x2843, which
    // RFC 9114 section 9 tells the peer to ignore.
    #expect(framed != capsule)
    #expect(framed.first == 0x00)
}

/// A DATA frame may carry several capsules, and a capsule may be split across
/// DATA frames; both survive the decoder.
@Test
func connectCapsuleDecoderReadsDataFramedCapsulesAcrossFrameBoundaries() throws {
    let first = try connectCapsule(type: 0x2843, payload: Data(repeating: 0x61, count: 5))
    let second = try connectCapsule(type: 0x78ae, payload: Data())

    var decoder = InteroperableCONNECTCapsuleDecoder()
    let together = try dataFrame(first + second)
    #expect(try decoder.append(together) == [first, second])
    #expect(!decoder.hasPendingBytes)

    var split = InteroperableCONNECTCapsuleDecoder()
    #expect(try split.append(dataFrame(first).prefix(3)) == [])
    #expect(split.hasPendingBytes, "half a DATA frame header is pending, not a closed stream")
    #expect(try split.append(Data(dataFrame(first).dropFirst(3)) + dataFrame(second)) == [first, second])
    #expect(!split.hasPendingBytes)
}

/// A capsule that spans a frame boundary inside its payload is only emitted once
/// its last byte has arrived.
@Test
func connectCapsuleDecoderHoldsACapsuleSplitAcrossDataFrames() throws {
    let capsule = try connectCapsule(type: 0x2843, payload: Data(repeating: 0x62, count: 16))
    let splitAt = capsule.count - 4

    var decoder = InteroperableCONNECTCapsuleDecoder()
    #expect(try decoder.append(try dataFrame(capsule.prefix(splitAt))) == [])
    #expect(decoder.hasPendingBytes)
    #expect(try decoder.append(try dataFrame(Data(capsule.dropFirst(splitAt)))) == [capsule])
    #expect(!decoder.hasPendingBytes)
    _ = capsule  // the capsule's own bytes are unchanged by the framing
}

/// The raw form is still *tolerated*: it is an unknown frame type, and RFC 9114
/// section 9 requires unknown frames to be ignored rather than reported. This is
/// what the five interop peers did to this runtime's raw capsules, and what this
/// runtime now does to a peer that still writes them.
@Test
func connectCapsuleDecoderSkipsTheRawUnframedFormWithoutReportingIt() throws {
    let capsule = try connectCapsule(type: 0x2843, payload: Data([0x01, 0x02, 0x03]))
    var decoder = InteroperableCONNECTCapsuleDecoder()
    #expect(try decoder.append(capsule) == [], "a raw capsule is skipped, not surfaced or rejected")
    #expect(!decoder.hasPendingBytes, "the whole raw capsule was consumed as one unknown frame")
}

/// A known non-DATA frame after CONNECT is H3_FRAME_UNEXPECTED (RFC 9114
/// section 4.4), so the decoder reports it instead of treating its bytes as a
/// capsule stream.
@Test
func connectCapsuleDecoderReportsAKnownNonDataFrame() throws {
    var decoder = InteroperableCONNECTCapsuleDecoder()
    let headers = try HTTP3Frame(type: HTTP3FrameType.headers, payload: Data([0x00])).encode()
    #expect(throws: HTTP3ConnectionError.self) {
        _ = try decoder.append(headers)
    }
    do {
        _ = try decoder.append(headers)
    } catch let error as HTTP3ConnectionError {
        #expect(error.code == .frameUnexpected)
    }
}

/// A stream that ends mid-frame or mid-capsule is a truncation, which the reader
/// distinguishes from the orderly close a bare FIN is.
@Test
func connectCapsuleDecoderReportsTruncatedUnitsAsPending() throws {
    let capsule = try connectCapsule(type: 0x2843, payload: Data(repeating: 0x63, count: 8))

    var partialCapsule = InteroperableCONNECTCapsuleDecoder()
    _ = try partialCapsule.append(try dataFrame(capsule.dropLast()))
    #expect(partialCapsule.hasPendingBytes)

    var partialHeader = InteroperableCONNECTCapsuleDecoder()
    _ = try partialHeader.append(Data([0x00]))
    #expect(partialHeader.hasPendingBytes)
}
