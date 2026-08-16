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
