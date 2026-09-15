import Foundation
import Testing
import WebTransportTLSCore
import WebTransportQUICCore

// MARK: - CRYPTO stream buffering limits

/// CRYPTO frames carry an arbitrary offset and are processed before anything is
/// authenticated, so a peer can scatter bytes across the offset space and make
/// the receiver hold them. RFC 9000 section 7.5 requires a ceiling.
@Test
func cryptoReassemblyRefusesToBufferWithoutLimit() throws {
    var reassembler = TLSCryptoStreamReassembler(maximumBufferedBytes: 128)

    // Scatter single bytes far apart so nothing ever becomes contiguous.
    var offset: UInt64 = 0
    var accepted = 0
    do {
        while offset < 1_000_000 {
            try reassembler.append(offset: offset, data: Data([0x41]))
            accepted += 1
            offset += 4_096
        }
        Issue.record("the reassembler accepted an unbounded amount of scattered data")
    } catch {
        // Expected once the ceiling is reached.
    }
    #expect(accepted <= 128)
    #expect(reassembler.bufferedByteCount <= 128)
}

/// Re-sending bytes already held must not count against the ceiling, or an
/// honest peer retransmitting a lost CRYPTO frame would be refused.
@Test
func cryptoReassemblyDoesNotChargeForRetransmittedBytes() throws {
    var reassembler = TLSCryptoStreamReassembler(maximumBufferedBytes: 8)
    let payload = Data([1, 2, 3, 4, 5, 6, 7, 8])

    try reassembler.append(offset: 0, data: payload)
    #expect(reassembler.bufferedByteCount == 8)

    // The same bytes again: already held, so still within the ceiling.
    try reassembler.append(offset: 0, data: payload)
    #expect(reassembler.bufferedByteCount == 8)
    #expect(reassembler.contiguousBytes() == payload)
}

/// A peer that contradicts itself about a byte it already sent is still refused.
@Test
func cryptoReassemblyStillRejectsConflictingOverlap() throws {
    var reassembler = TLSCryptoStreamReassembler()
    try reassembler.append(offset: 0, data: Data([0xAA]))
    #expect(throws: (any Error).self) {
        try reassembler.append(offset: 0, data: Data([0xBB]))
    }
}

/// Ordinary in-order reassembly is unchanged.
@Test
func cryptoReassemblyStillJoinsOutOfOrderFragments() throws {
    var reassembler = TLSCryptoStreamReassembler()
    try reassembler.append(offset: 4, data: Data([5, 6, 7, 8]))
    try reassembler.append(offset: 0, data: Data([1, 2, 3, 4]))
    #expect(reassembler.contiguousBytes() == Data([1, 2, 3, 4, 5, 6, 7, 8]))
}

/// The ceiling bounds bytes *waiting for a gap*, not every byte the connection has
/// ever carried.
///
/// Consumed bytes are retained so a conflicting retransmission is still detected, so
/// counting rows made the ceiling a lifetime cap: a peer that completed a large
/// handshake could no longer deliver a legitimate post-handshake message such as a
/// NewSessionTicket or KeyUpdate, and was disconnected instead.
@Test
func cryptoReassemblyCeilingDoesNotBecomeALifetimeCap() throws {
    var decoder = TLSHandshakeFlightDecoder()

    var certificate = Data([0x0b, 0x00, 0x9c, 0x40])  // type 11, length 40_000
    certificate.append(Data(repeating: 0x41, count: 40_000))
    #expect(try decoder.receive(frame: .crypto(offset: 0, data: certificate)).count == 1)
    #expect(decoder.consumedByteCount == 40_004)

    var postHandshake = Data()
    for _ in 0..<4_000 {
        postHandshake.append(contentsOf: [0x14, 0x00, 0x00, 0x04, 1, 2, 3, 4])  // Finished
    }
    _ = try decoder.receive(frame: .crypto(offset: UInt64(certificate.count), data: postHandshake))

    #expect(decoder.consumedByteCount > UInt64(64 * 1024))
    #expect(decoder.reassembler.pendingByteCount == 0)
}

// MARK: - F-swift-line-security-08: quadratic accounting and unbounded retention

/// Consumed CRYPTO bytes used to be retained forever so that a conflicting
/// retransmission could always be detected, which made the buffer grow with the
/// connection. Conflict detection only needs a recent window, so rows that fall
/// out of it are dropped and retention stays bounded.
@Test
func cryptoReassemblyBoundsRetainedConsumedBytes() throws {
    var reassembler = TLSCryptoStreamReassembler(maximumBufferedBytes: 64)

    for chunk in 0..<256 {
        try reassembler.append(
            offset: UInt64(chunk * 64),
            data: Data(repeating: 0x41, count: 64)
        )
        reassembler.markConsumed(below: UInt64((chunk + 1) * 64))
        #expect(reassembler.pendingByteCount == 0)
    }

    #expect(
        reassembler.bufferedByteCount <= 4 * 1024 + 64,
        "16 KiB was consumed, so keeping all of it means consumed rows are never dropped")
}

/// The handshake transcript appended every decoded message with no ceiling, so a
/// peer that kept sending well-formed handshake messages grew it for the
/// connection's lifetime.
@Test
func handshakeTranscriptRetentionIsBounded() throws {
    var transcript = TLS13Transcript()
    let message = TLSHandshakeMessage(type: .finished, body: Data())

    var threw = false
    do {
        for _ in 0..<(1024 * 1024 / 4 + 2) {
            try transcript.append(message)
        }
    } catch {
        threw = true
    }

    #expect(threw, "the transcript accepted more than a megabyte of handshake messages")
    #expect(transcript.encodedMessages.count <= 1024 * 1024)
}

/// `append` used to recompute the pending-byte count by scanning the whole buffer
/// once per frame, so a peer feeding one-byte CRYPTO frames made reassembly
/// quadratic in the buffered byte count. The stored counter makes each frame O(1).
@Test
func cryptoReassemblyPerFrameCostDoesNotGrowWithBufferedBytes() throws {
    var reassembler = TLSCryptoStreamReassembler(maximumBufferedBytes: 200_000)
    try reassembler.append(offset: 0, data: Data(repeating: 0x11, count: 8))
    reassembler.markConsumed(below: 8)

    let frameCount = 50_000
    let started = Date()
    for index in 0..<frameCount {
        try reassembler.append(offset: UInt64(8 + index), data: Data([UInt8(index & 0xff)]))
    }
    let elapsed = Date().timeIntervalSince(started)

    #expect(reassembler.pendingByteCount == frameCount)
    #expect(
        elapsed < 4,
        "\(frameCount) one-byte CRYPTO frames took \(elapsed)s with a \(reassembler.pendingByteCount)-byte buffer; per-frame accounting must not rescan the buffer"
    )
}
