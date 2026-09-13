import Foundation
import Testing
@testable import WebTransportNetworkRuntime

/// WebTransport issue #24: a stream read before the peer has written anything.
///
/// Measured against the real framework on macOS 26.6.2: `receive(atMost:)` waits for at
/// least one byte (`atLeast` defaults to 1), and a stream the peer opens without writing
/// to it is not even delivered to the inbound-stream handler until its first byte
/// arrives. An empty chunk is therefore never "nothing yet" — it is the peer having
/// ended the stream — but the codec reports it as `truncated(needed: 1, available: 0)`,
/// which reads like an internal truncation. These tests pin how the runtime tells those
/// apart, which is the part a test can construct.
@Test
func aStreamChunkIsClassifiedAsBytesAWaitOrAPeerEnding() {
    #expect(
        InteroperableQUICHelpers.decideFirstChunk(Data([0x01]), endOfStream: false)
            == .bytes(Data([0x01])))

    // An empty chunk on a stream that has not ended says nothing, so a reader waits for
    // the next one rather than treating "no bytes yet" as "the stream is over".
    #expect(InteroperableQUICHelpers.decideFirstChunk(Data(), endOfStream: false) == .keepWaiting)

    // An empty chunk at end of stream is a peer that ended the stream before writing it.
    #expect(InteroperableQUICHelpers.decideFirstChunk(Data(), endOfStream: true) == .peerClosed)

    // Data and the ending together are the ordinary last chunk, not an ending without data.
    #expect(
        InteroperableQUICHelpers.decideFirstChunk(Data([0x01]), endOfStream: true)
            == .bytes(Data([0x01])))
}

/// The error a caller now sees in place of the codec's truncation, and the stream it names.
@Test
func aPeerEndingAStreamWithoutDataIsReportedWithItsStream() {
    let error = WebTransportNetworkRuntimeError.peerClosedStreamWithoutData(streamID: 12)
    #expect(
        error.description
            == "the peer ended stream 12 before sending any bytes; "
            + "the stream cannot be used and the peer is not following the protocol")
}
