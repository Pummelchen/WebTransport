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

    private var bytesByOffset: [UInt64: UInt8]
    public let maximumBufferedBytes: Int

    /// Everything below this offset has already been handed to the decoder.
    ///
    /// The bytes themselves are deliberately retained rather than deleted: they are
    /// what a conflicting retransmission is checked against, so a peer that sends
    /// different bytes for an offset it already used is still rejected after the
    /// decoder has moved past it. This watermark is what lets the ceiling below
    /// measure only what is still waiting for a gap.
    private var consumedByteCount: UInt64 = 0

    public init(maximumBufferedBytes: Int = TLSCryptoStreamReassembler.defaultMaximumBufferedBytes) {
        self.bytesByOffset = [:]
        self.maximumBufferedBytes = max(1, maximumBufferedBytes)
    }

    /// How many bytes are currently held, including those already consumed.
    public var bufferedByteCount: Int {
        bytesByOffset.count
    }

    /// How many held bytes the decoder has not yet consumed.
    ///
    /// This, not the total row count, is the quantity ``maximumBufferedBytes`` bounds.
    /// Counting every row made the ceiling a lifetime cap: consumed bytes are retained
    /// for conflict detection, so a peer that completed a large handshake could no
    /// longer deliver a legitimate post-handshake message such as a NewSessionTicket
    /// or KeyUpdate, and was disconnected instead.
    ///
    /// A peer scattering bytes across the offset space never completes a message, so
    /// the watermark never moves and this figure grows with every byte received —
    /// which is the attack the ceiling exists to stop.
    public var pendingByteCount: Int {
        recomputePendingByteCount()
    }

    /// Counts held bytes at or above the watermark.
    ///
    /// `append` reads this once per frame and increments a local from there, so a large
    /// frame is linear rather than quadratic. Recomputing per byte would make a 16 KB
    /// CRYPTO frame cost hundreds of millions of dictionary probes, which is the kind of
    /// peer-controlled cost the ceiling exists to prevent.
    private func recomputePendingByteCount() -> Int {
        guard consumedByteCount > 0 else {
            return bytesByOffset.count
        }
        // Contiguous fragmented data starts at the current watermark, so the pending
        // count is every row except the consumed prefix below the lowest live key.
        guard let lowestLive = bytesByOffset.keys.filter({ $0 >= consumedByteCount }).min() else {
            return 0
        }
        return bytesByOffset.count - bytesByOffset.keys.count(where: { $0 < lowestLive })
    }

    /// Records that the decoder has consumed everything below `offset`.
    ///
    /// The bytes stay in place; only the accounting changes.
    public mutating func markConsumed(below offset: UInt64) {
        if offset > consumedByteCount {
            consumedByteCount = offset
        }
    }

    public mutating func append(offset: UInt64, data: Data) throws {
        guard UInt64(data.count) <= UInt64.max - offset else {
            throw QUICCodecError.valueOutOfRange("CRYPTO data offset would overflow")
        }

        var pendingBytes = pendingByteCount

        for (index, byte) in data.enumerated() {
            let absoluteOffset = offset + UInt64(index)
            if let existing = bytesByOffset[absoluteOffset] {
                guard existing == byte else {
                    throw QUICCodecError.malformed("conflicting CRYPTO data overlap")
                }
                continue
            }
            guard pendingBytes < maximumBufferedBytes else {
                throw QUICCodecError.valueOutOfRange(
                    "CRYPTO stream buffer exceeded \(maximumBufferedBytes) bytes"
                )
            }
            bytesByOffset[absoluteOffset] = byte
            pendingBytes += 1
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
