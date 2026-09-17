import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore

/// The HTTP/3 framing of the capsule protocol on a CONNECT request stream.
///
/// RFC 9297 section 3.1 defines the "data stream" of an HTTP request, and in
/// HTTP/3 that stream is "all bytes sent in DATA frames with the corresponding
/// stream ID". Section 3.2 then defines the Capsule Protocol as the *contents*
/// of that data stream. RFC 9114 section 4.4 says the same from the CONNECT
/// side: once CONNECT has completed, "only DATA frames are permitted to be sent
/// on the stream", and receipt of any other known frame type is a connection
/// error of type `H3_FRAME_UNEXPECTED`.
///
/// Writing a capsule's type and length straight to the stream therefore does not
/// put a capsule on the wire: it puts a frame of an unknown type there, which
/// RFC 9114 section 9 requires the peer to ignore. The capsule is silently
/// dropped, never rejected. Three independent peers agree on the framed form:
///
/// - `web-transport-proto`'s `Http3CapsuleReader` documents that "capsule data
///   is carried inside DATA frames (RFC 9297 Section 3.2)" and skips non-DATA
///   frames; `web-transport-quinn` wraps the close capsule in a DATA frame.
/// - aioquic's `H3Connection.send_data` wraps its payload in a DATA frame, and
///   its parser emits data for DATA frames only — the WPT WebTransport H3
///   server reads its session stream as `DataReceived`.
/// - Chromium's quiche writes the DATA frame header in `WriteOrBufferBody`
///   before `WriteCapsule`'s bytes, and reads capsules from the request body.
///
/// This type is that framing and nothing else; the capsule TLV itself stays the
/// business of `WebTransportSessionManager`.
internal enum InteroperableCONNECTCapsuleFraming {
    /// The largest CONNECT-stream capsule payload permitted by
    /// draft-ietf-webtrans-http3-16, in bytes.
    ///
    /// The only CONNECT-stream capsule whose payload is neither empty nor a
    /// single QUIC varint is WT_CLOSE_SESSION: it carries a 32-bit application
    /// error code followed by a UTF-8 message that the draft (Section 6) caps
    /// at `wtCloseSessionMaxMessageBytes` (1024) bytes. Flow-control capsules
    /// carry one varint and WT_DRAIN_SESSION is empty, so a conforming peer
    /// can never declare a larger payload. The reader rejects a declared
    /// length above this bound on the capsule header alone — before waiting
    /// for, and therefore before buffering, the payload — so a peer cannot
    /// pin unbounded memory by announcing a huge capsule and then stalling.
    static let maximumCapsulePayloadBytes =
        WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes + 4

    /// Wraps one capsule in the DATA frame that carries it on the CONNECT stream.
    static func wrap(_ capsule: Data) throws -> Data {
        try HTTP3Frame(type: HTTP3FrameType.data, payload: capsule).encode()
    }

    /// Removes one complete capsule TLV from the front of `buffer`.
    ///
    /// Returns `nil` when the buffer does not hold a whole capsule yet, so a
    /// capsule split across DATA frames stays pending rather than being
    /// reported as a truncation.
    static func popCompleteCapsule(from buffer: inout Data) throws -> Data? {
        guard !buffer.isEmpty else {
            return nil
        }
        var cursor = QUICByteCursor(buffer)
        do {
            _ = try QUICVarInt.decode(from: &cursor)
            let payloadLength = try QUICVarInt.decode(from: &cursor)
            guard payloadLength <= UInt64(Int.max) else {
                throw QUICCodecError.valueOutOfRange("CONNECT capsule length exceeds Int.max")
            }
            // Reject an over-long declaration on the header alone. Waiting for
            // the announced payload would let a peer keep this loop buffering
            // (and re-opening flow-control credit) without bound.
            guard payloadLength <= UInt64(maximumCapsulePayloadBytes) else {
                throw QUICCodecError.valueOutOfRange(
                    "CONNECT capsule payload length \(payloadLength) exceeds the draft-16 maximum of "
                        + "\(maximumCapsulePayloadBytes) bytes"
                )
            }
            let headerLength = buffer.count - cursor.remaining
            let (capsuleLength, overflow) = headerLength.addingReportingOverflow(Int(payloadLength))
            guard !overflow else {
                throw QUICCodecError.valueOutOfRange("CONNECT capsule length overflow")
            }
            guard buffer.count >= capsuleLength else {
                return nil
            }
            let capsule = Data(buffer.prefix(capsuleLength))
            buffer.removeFirst(capsuleLength)
            return capsule
        } catch QUICCodecError.truncated {
            return nil
        }
    }
}

/// Decodes the capsule protocol of a CONNECT request stream from its HTTP/3
/// frames.
///
/// The stream carries DATA frames whose payloads concatenate to the data stream
/// (RFC 9114 section 4.4, RFC 9297 section 3.1). A capsule may be split across
/// DATA frames and one DATA frame may carry several capsules, so the decoder
/// keeps the two buffers apart: complete frame payload bytes move into a capsule
/// buffer from which complete capsules are popped.
///
/// Frame payloads are moved through in chunk-sized pieces rather than buffered
/// whole, so a peer that announces a huge DATA frame cannot make the runtime
/// hold it. A non-DATA frame is skipped when it is unknown — RFC 9114 section 9
/// requires unknown frame types to be ignored, and the historical raw-capsule
/// form is exactly such a frame — and reported when it is one RFC 9114 section
/// 4.4 forbids on a CONNECT stream.
internal struct InteroperableCONNECTCapsuleDecoder {
    private var frameBytes = Data()
    private var capsuleBytes = Data()
    private var remainingDataBytes: Int?
    private var remainingSkippedBytes: Int?

    /// Whether bytes are held that do not yet form a complete frame or capsule.
    ///
    /// A stream that ends with any of them ended mid-frame or mid-capsule, which
    /// is a truncation rather than an orderly close.
    var hasPendingBytes: Bool {
        !frameBytes.isEmpty || !capsuleBytes.isEmpty || remainingDataBytes != nil
            || remainingSkippedBytes != nil
    }

    /// Feeds stream bytes and returns every capsule they completed, in order.
    mutating func append(_ bytes: Data) throws -> [Data] {
        frameBytes.append(bytes)
        try moveDataStreamBytes()
        var capsules: [Data] = []
        while let capsule = try InteroperableCONNECTCapsuleFraming.popCompleteCapsule(from: &capsuleBytes) {
            capsules.append(capsule)
        }
        return capsules
    }

    private mutating func moveDataStreamBytes() throws {
        while true {
            if let remaining = remainingDataBytes {
                let taken = min(remaining, frameBytes.count)
                capsuleBytes.append(frameBytes.prefix(taken))
                frameBytes.removeFirst(taken)
                remainingDataBytes = remaining > taken ? remaining - taken : nil
                if remainingDataBytes != nil {
                    return
                }
            }
            if let remaining = remainingSkippedBytes {
                let taken = min(remaining, frameBytes.count)
                frameBytes.removeFirst(taken)
                remainingSkippedBytes = remaining > taken ? remaining - taken : nil
                if remainingSkippedBytes != nil {
                    return
                }
            }
            guard !frameBytes.isEmpty else {
                return
            }
            var cursor = QUICByteCursor(frameBytes)
            let type: UInt64
            let length: UInt64
            do {
                type = try QUICVarInt.decode(from: &cursor)
                length = try QUICVarInt.decode(from: &cursor)
            } catch QUICCodecError.truncated {
                return
            }
            guard length <= UInt64(Int.max) else {
                throw HTTP3ConnectionError(
                    code: .frameUnexpected,
                    reason: "HTTP/3 frame length \(length) on a CONNECT stream exceeds Int.max"
                )
            }
            frameBytes.removeFirst(frameBytes.count - cursor.remaining)
            if type == HTTP3FrameType.data {
                remainingDataBytes = Int(length)
            } else if Self.forbiddenOnConnectStream.contains(type) {
                throw HTTP3ConnectionError(
                    code: .frameUnexpected,
                    reason: "HTTP/3 frame type \(type) is not permitted on a CONNECT stream "
                        + "(RFC 9114 section 4.4)"
                )
            } else {
                remainingSkippedBytes = Int(length)
            }
        }
    }

    /// Frame types RFC 9114 forbids after CONNECT.
    ///
    /// Every HTTP/3 frame other than DATA is known but not permitted there, and
    /// the HTTP/2 frame types with no HTTP/3 equivalent "MUST NOT be sent, and
    /// their receipt MUST be treated as a connection error of type
    /// H3_FRAME_UNEXPECTED" (RFC 9114 section 7.2.8). Reserved frame types are
    /// deliberately absent: section 7.2.8 reserves them so that unknown types can
    /// be ignored, which section 9 requires.
    private static let forbiddenOnConnectStream: Set<UInt64> = [
        HTTP3FrameType.headers,
        HTTP3FrameType.cancelPush,
        HTTP3FrameType.settings,
        HTTP3FrameType.pushPromise,
        HTTP3FrameType.goaway,
        HTTP3FrameType.maxPushID,
        0x02,  // HTTP/2 PRIORITY
        0x06,  // HTTP/2 PING
        0x08,  // HTTP/2 WINDOW_UPDATE
        0x09,  // HTTP/2 CONTINUATION
    ]
}
