import Foundation
import WebTransportQUICCore

public struct TLSHandshakeFlight: Equatable, Sendable {
    public var messages: [TLSHandshakeMessage]

    public init(messages: [TLSHandshakeMessage]) {
        self.messages = messages
    }

    public func encodedBytes() throws -> Data {
        var output = Data()
        for message in messages {
            output.append(try message.encode())
        }
        return output
    }

    public func cryptoFrames(startingOffset: UInt64 = 0, maxFramePayloadBytes: Int) throws -> [QUICFrame] {
        guard maxFramePayloadBytes > 0 else {
            throw QUICCodecError.valueOutOfRange("CRYPTO frame payload size must be positive")
        }

        let bytes = try encodedBytes()
        guard UInt64(bytes.count) <= UInt64.max - startingOffset else {
            throw QUICCodecError.valueOutOfRange("CRYPTO frame offset would overflow")
        }
        guard !bytes.isEmpty else {
            return []
        }

        var frames: [QUICFrame] = []
        var cursor = bytes.startIndex
        var offset = startingOffset
        while cursor < bytes.endIndex {
            let end = bytes.index(cursor, offsetBy: maxFramePayloadBytes, limitedBy: bytes.endIndex) ?? bytes.endIndex
            let chunk = Data(bytes[cursor..<end])
            frames.append(.crypto(offset: offset, data: chunk))
            offset += UInt64(chunk.count)
            cursor = end
        }
        return frames
    }
}

public struct TLSCryptoStreamReassembler: Equatable, Sendable {
    /// How many bytes of CRYPTO stream data may be held while waiting for the
    /// gaps between them to be filled.
    ///
    /// CRYPTO frames carry an arbitrary offset and are processed before the
    /// handshake has authenticated anything, so without a ceiling a peer can
    /// scatter a few bytes across the offset space and make the receiver hold
    /// them indefinitely. RFC 9000 section 7.5 requires a limit for exactly this
    /// and provides CRYPTO_BUFFER_EXCEEDED to report it. A TLS handshake that
    /// needs more than this is not one worth completing.
    ///
    /// Note that the cost per byte is far above one: each is held as its own
    /// dictionary entry so that out-of-order arrival is easy to express, which
    /// trades memory for simplicity. The ceiling is on the byte count, so the
    /// real footprint is a multiple of it.
    public static let defaultMaximumBufferedBytes = 64 * 1024

    /// How many already-consumed bytes stay behind the watermark so that a
    /// conflicting retransmission of recent data is still detected.
    ///
    /// Consumed bytes used to be retained forever, which made the buffer grow with
    /// the connection. Conflict detection only has to cover a recent window: a
    /// retransmission that matters is one racing the bytes the decoder is working
    /// on, not one arriving long after they were consumed.
    public static let defaultConsumedHistoryBytes = 4 * 1024

    private var bytesByOffset: [UInt64: UInt8]
    public let maximumBufferedBytes: Int
    public let consumedHistoryBytes: Int

    /// Everything below this offset has already been handed to the decoder.
    ///
    /// This watermark lets the ceiling below measure only what is still waiting for
    /// a gap. Bytes just below it are kept for a bounded window so that a peer
    /// contradicting itself about a recent byte is still rejected.
    private var consumedByteCount: UInt64 = 0

    /// Everything below this offset has been dropped from ``bytesByOffset`` too.
    private var prunedByteCount: UInt64 = 0

    /// Held bytes at or above ``consumedByteCount``.
    ///
    /// Maintained incrementally rather than recomputed: recomputing scanned the
    /// whole map once per frame, so a peer feeding one-byte CRYPTO frames made
    /// reassembly quadratic in the buffered byte count.
    private var pendingByteTotal: Int = 0

    public init(
        maximumBufferedBytes: Int = TLSCryptoStreamReassembler.defaultMaximumBufferedBytes,
        consumedHistoryBytes: Int = TLSCryptoStreamReassembler.defaultConsumedHistoryBytes
    ) {
        self.bytesByOffset = [:]
        self.maximumBufferedBytes = max(1, maximumBufferedBytes)
        self.consumedHistoryBytes = max(0, consumedHistoryBytes)
    }

    /// How many bytes are currently held, including the bounded consumed history.
    public var bufferedByteCount: Int {
        bytesByOffset.count
    }

    /// How many held bytes the decoder has not yet consumed.
    ///
    /// This, not the total row count, is the quantity ``maximumBufferedBytes`` bounds.
    /// Counting every row made the ceiling a lifetime cap: consumed bytes were
    /// retained for conflict detection, so a peer that completed a large handshake
    /// could no longer deliver a legitimate post-handshake message such as a
    /// NewSessionTicket or KeyUpdate, and was disconnected instead.
    ///
    /// A peer scattering bytes across the offset space never completes a message, so
    /// the watermark never moves and this figure grows with every byte received —
    /// which is the attack the ceiling exists to stop.
    public var pendingByteCount: Int {
        pendingByteTotal
    }

    /// Records that the decoder has consumed everything below `offset`.
    ///
    /// The watermark moves over the contiguous run the decoder assembled, so the
    /// walk costs one step per consumed byte in total rather than one per frame.
    /// Bytes within ``consumedHistoryBytes`` of the new watermark stay held for
    /// conflict detection; older ones are dropped.
    public mutating func markConsumed(below offset: UInt64) {
        guard offset > consumedByteCount else {
            return
        }

        // Stop at the first gap. The decoder only advances over a contiguous
        // prefix, so this is exactly the newly consumed run; it also bounds the
        // walk for a caller that marks past the data it actually received (those
        // rows stay counted, which is the conservative outcome).
        var runEnd = consumedByteCount
        while runEnd < offset, bytesByOffset[runEnd] != nil {
            pendingByteTotal -= 1
            runEnd += 1
        }
        consumedByteCount = offset

        // Drop conflict-detection rows outside the grace window. Both the window
        // and the discovered run bound this walk.
        let keepFrom = offset > UInt64(consumedHistoryBytes) ? offset - UInt64(consumedHistoryBytes) : 0
        let pruneEnd = min(keepFrom, runEnd)
        var cursor = prunedByteCount
        while cursor < pruneEnd {
            bytesByOffset.removeValue(forKey: cursor)
            cursor += 1
        }
        prunedByteCount = max(prunedByteCount, pruneEnd)
    }

    public mutating func append(offset: UInt64, data: Data) throws {
        guard UInt64(data.count) <= UInt64.max - offset else {
            throw QUICCodecError.valueOutOfRange("CRYPTO data offset would overflow")
        }

        for (index, byte) in data.enumerated() {
            let absoluteOffset = offset + UInt64(index)
            if let existing = bytesByOffset[absoluteOffset] {
                guard existing == byte else {
                    throw QUICCodecError.malformed("conflicting CRYPTO data overlap")
                }
                continue
            }
            guard pendingByteTotal < maximumBufferedBytes else {
                throw QUICCodecError.valueOutOfRange(
                    "CRYPTO stream buffer exceeded \(maximumBufferedBytes) bytes"
                )
            }
            bytesByOffset[absoluteOffset] = byte
            if absoluteOffset >= consumedByteCount {
                pendingByteTotal += 1
            }
        }
    }

    public func contiguousBytes(from offset: UInt64 = 0) -> Data {
        var output = Data()
        var cursor = offset
        while let byte = bytesByOffset[cursor] {
            output.append(byte)
            guard cursor < UInt64.max else {
                break
            }
            cursor += 1
        }
        return output
    }
}

public struct TLSHandshakeFlightDecoder: Equatable, Sendable {
    public private(set) var reassembler: TLSCryptoStreamReassembler
    public private(set) var transcript: TLS13Transcript
    public private(set) var consumedByteCount: UInt64

    public init(transcript: TLS13Transcript = TLS13Transcript()) {
        self.reassembler = TLSCryptoStreamReassembler()
        self.transcript = transcript
        self.consumedByteCount = 0
    }

    public mutating func receive(frame: QUICFrame) throws -> [TLSHandshakeMessage] {
        guard case .crypto(let offset, let data) = frame else {
            throw QUICCodecError.malformed("TLS handshake flight decoder only accepts CRYPTO frames")
        }

        try reassembler.append(offset: offset, data: data)
        return try decodeAvailableMessages()
    }

    public mutating func receive(frames: [QUICFrame]) throws -> [TLSHandshakeMessage] {
        var output: [TLSHandshakeMessage] = []
        for frame in frames {
            output.append(contentsOf: try receive(frame: frame))
        }
        return output
    }

    public mutating func appendTranscript(_ message: TLSHandshakeMessage) throws {
        try transcript.append(message)
    }

    private mutating func decodeAvailableMessages() throws -> [TLSHandshakeMessage] {
        let data = reassembler.contiguousBytes(from: consumedByteCount)
        var localOffset = data.startIndex
        var decoded: [TLSHandshakeMessage] = []

        while data.distance(from: localOffset, to: data.endIndex) >= 4 {
            guard let type = TLSHandshakeType(rawValue: data[localOffset]) else {
                throw QUICCodecError.malformed("unknown TLS handshake type")
            }
            let lengthOffset = data.index(after: localOffset)
            let bodyLength =
                (Int(data[lengthOffset]) << 16) | (Int(data[data.index(after: lengthOffset)]) << 8) | Int(data[data.index(lengthOffset, offsetBy: 2)])
            let messageLength = 4 + bodyLength
            guard data.distance(from: localOffset, to: data.endIndex) >= messageLength else {
                break
            }

            let bodyStart = data.index(localOffset, offsetBy: 4)
            let bodyEnd = data.index(bodyStart, offsetBy: bodyLength)
            let message = TLSHandshakeMessage(type: type, body: Data(data[bodyStart..<bodyEnd]))
            try transcript.append(message)
            decoded.append(message)
            guard UInt64(messageLength) <= UInt64.max - consumedByteCount else {
                throw QUICCodecError.valueOutOfRange("consumed CRYPTO byte count would overflow")
            }
            consumedByteCount += UInt64(messageLength)
            localOffset = bodyEnd
        }

        // Tell the reassembler what has been consumed so its ceiling measures bytes
        // still waiting for a gap rather than every byte ever carried.
        reassembler.markConsumed(below: consumedByteCount)

        return decoded
    }
}
