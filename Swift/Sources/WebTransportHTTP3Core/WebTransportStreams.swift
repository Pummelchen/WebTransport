import Foundation
import WebTransportQUICCore

public enum WebTransportStreamForm: Equatable, Sendable {
    case bidirectional
    case unidirectional
}

public struct WebTransportStreamPrefix: Equatable, Sendable {
    public let form: WebTransportStreamForm
    public let sessionID: WebTransportSessionID
    public let bytesConsumed: Int
    public let remainingPayload: Data

    public init(
        form: WebTransportStreamForm,
        sessionID: WebTransportSessionID,
        bytesConsumed: Int,
        remainingPayload: Data
    ) {
        self.form = form
        self.sessionID = sessionID
        self.bytesConsumed = bytesConsumed
        self.remainingPayload = remainingPayload
    }
}

public enum WebTransportStreamSignaling {
    public static func serializePrefix(
        form: WebTransportStreamForm,
        sessionID: UInt64,
        constants: WebTransportHTTP3DraftConstants = .current
    ) throws -> Data {
        var output = Data()
        let marker = try streamMarker(for: form, constants: constants)
        output.append(try QUICVarInt.encode(marker))
        output.append(try QUICVarInt.encode(sessionID))
        return output
    }

    public static func serializeBidirectionalPrefix(
        sessionID: UInt64,
        constants: WebTransportHTTP3DraftConstants = .current
    ) throws -> Data {
        try serializePrefix(form: .bidirectional, sessionID: sessionID, constants: constants)
    }

    public static func serializeUnidirectionalPrefix(
        sessionID: UInt64,
        constants: WebTransportHTTP3DraftConstants = .current
    ) throws -> Data {
        try serializePrefix(form: .unidirectional, sessionID: sessionID, constants: constants)
    }

    /// Reports whether `bytes` begins with a WebTransport stream marker.
    ///
    /// Callers use this to separate two outcomes that ``parsePrefix(_:constants:)``
    /// reports identically as a thrown error: a stream that simply is not
    /// prefixed — the normal shape of an HTTP/3 extended CONNECT request stream —
    /// and a stream that *is* prefixed but carries malformed contents, which is a
    /// protocol violation. Treating the second as the first would let a peer
    /// steer the receiver onto a non-error path with invalid input.
    ///
    /// This inspects only the leading marker and never throws; a truncated or
    /// undecodable varint reports `false`, leaving the payload to be rejected by
    /// whichever parser owns it.
    public static func hasStreamPrefix(
        _ bytes: Data,
        constants: WebTransportHTTP3DraftConstants = .current
    ) -> Bool {
        var cursor = QUICByteCursor(bytes)
        guard let marker = try? QUICVarInt.decode(from: &cursor) else {
            return false
        }
        return marker == constants.wtStreamFrame || marker == constants.webTransportStream
    }

    public static func parsePrefix(
        _ bytes: Data,
        constants: WebTransportHTTP3DraftConstants = .current
    ) throws -> WebTransportStreamPrefix {
        var cursor = QUICByteCursor(bytes)
        let marker = try QUICVarInt.decode(from: &cursor)
        let form: WebTransportStreamForm
        switch marker {
        case constants.wtStreamFrame:
            form = .bidirectional
        case constants.webTransportStream:
            form = .unidirectional
        default:
            throw QUICCodecError.malformed("unknown WebTransport stream marker: \(marker)")
        }

        let sessionRaw = try QUICVarInt.decode(from: &cursor)
        let sessionID: WebTransportSessionID
        do {
            sessionID = try WebTransportSessionID.fromRequestStreamID(sessionRaw)
        } catch {
            throw WebTransportDraft16Error(
                kind: .h3ID,
                message: "invalid WebTransport stream session ID"
            )
        }
        let remainingPayload = try cursor.readBytes(count: cursor.remaining)
        return WebTransportStreamPrefix(
            form: form,
            sessionID: sessionID,
            bytesConsumed: bytes.count - cursor.remaining,
            remainingPayload: remainingPayload
        )
    }

    private static func streamMarker(
        for form: WebTransportStreamForm,
        constants: WebTransportHTTP3DraftConstants
    ) throws -> UInt64 {
        switch form {
        case .bidirectional:
            return constants.wtStreamFrame
        case .unidirectional:
            return constants.webTransportStream
        }
    }
}

public struct WebTransportStreamState: Equatable, Sendable {
    public let streamID: UInt64
    public let sessionID: WebTransportSessionID
    public let form: WebTransportStreamForm
    public private(set) var quicStream: QUICStreamState
    /// Pending payloads in receive order, oldest first.
    ///
    /// A computed view over the storage below: the consumed prefix is retained in
    /// place until it is worth reclaiming, so the cost of removing the oldest
    /// payload is not proportional to how many are still buffered.
    public var bufferedPayloads: [Data] {
        Array(payloadStorage[payloadHead...])
    }
    public private(set) var bufferedPayloadBytes: Int
    public let maxBufferedBytes: Int

    /// Payloads in receive order, including the consumed prefix below ``payloadHead``.
    private var payloadStorage: [Data]
    /// How many leading entries of ``payloadStorage`` have already been popped.
    private var payloadHead: Int

    public init(
        streamID: UInt64,
        sessionID: WebTransportSessionID,
        form: WebTransportStreamForm,
        localRole: HTTP3ConnectionRole,
        maxSendOffset: UInt64,
        maxReceiveOffset: UInt64,
        maxBufferedBytes: Int
    ) throws {
        guard maxBufferedBytes >= 0 else {
            throw QUICCodecError.valueOutOfRange("stream receive buffer must not be negative")
        }

        self.streamID = streamID
        self.sessionID = sessionID
        self.form = form
        self.quicStream = QUICStreamState(
            id: streamID,
            localRole: localRole == .client ? .client : .server,
            maxSendOffset: maxSendOffset,
            maxReceiveOffset: maxReceiveOffset
        )
        self.bufferedPayloadBytes = 0
        self.maxBufferedBytes = maxBufferedBytes
        self.payloadStorage = []
        self.payloadHead = 0
    }

    public mutating func receivePayload(_ data: Data) throws {
        try bufferPayload(data)
    }

    /// Receives `data` and returns the payload the caller must observe next.
    ///
    /// This is what a read that immediately consumes its own arrival needs: the
    /// QUIC stream bookkeeping and the buffer ceiling are applied exactly as in
    /// ``receivePayload(_:)``, but a payload that arrives on an otherwise empty
    /// buffer is handed straight back instead of being appended and popped again.
    /// When an earlier payload is still pending the FIFO order is preserved: the
    /// arrival is buffered and the oldest pending payload is returned instead.
    public mutating func receivePayloadDeliveringImmediately(_ data: Data) throws -> Data {
        guard data.count <= max(0, maxBufferedBytes - bufferedPayloadBytes) else {
            throw QUICCodecError.malformed("WebTransport stream receive buffer limit exceeded")
        }

        let frame = QUICFrame.stream(id: streamID, offset: quicStream.receiveOffset, fin: false, data: data)
        _ = try quicStream.receive(frame)

        guard payloadHead < payloadStorage.count else {
            // Nothing pending, so this arrival is the read result. Drop the consumed
            // prefix so the storage does not keep a dead tail behind it.
            payloadStorage.removeAll(keepingCapacity: true)
            payloadHead = 0
            return data
        }

        payloadStorage.append(data)
        bufferedPayloadBytes += data.count
        return popPayload() ?? data
    }

    private mutating func bufferPayload(_ data: Data) throws {
        guard data.count <= max(0, maxBufferedBytes - bufferedPayloadBytes) else {
            throw QUICCodecError.malformed("WebTransport stream receive buffer limit exceeded")
        }

        let frame = QUICFrame.stream(id: streamID, offset: quicStream.receiveOffset, fin: false, data: data)
        _ = try quicStream.receive(frame)
        payloadStorage.append(data)
        bufferedPayloadBytes += data.count
    }

    public mutating func sendPayload(_ data: Data, fin: Bool = false) throws -> QUICFrame {
        try quicStream.send(data: data, fin: fin)
    }

    public mutating func popPayload() -> Data? {
        guard payloadHead < payloadStorage.count else {
            return nil
        }
        let first = payloadStorage[payloadHead]
        payloadHead += 1
        bufferedPayloadBytes -= first.count
        compactPayloadStorageIfWorthwhile()
        return first
    }

    /// Reclaims the consumed prefix once it is at least half the storage.
    ///
    /// Removing from the front moves every remaining element, so doing it per pop
    /// is what made draining a buffer quadratic. Waiting until the consumed prefix
    /// is as large as the live tail bounds the move to the work already paid for,
    /// which makes each pop amortised O(1).
    private mutating func compactPayloadStorageIfWorthwhile() {
        guard payloadHead > 0 else {
            return
        }
        guard payloadHead == payloadStorage.count || payloadHead * 2 >= payloadStorage.count else {
            return
        }
        payloadStorage.removeFirst(payloadHead)
        payloadHead = 0
    }

    /// Whether this endpoint owns the stream's send half (RFC 9000 section 2.1).
    ///
    /// A bulk teardown has to consult this before producing a RESET_STREAM: for
    /// a unidirectional stream the peer initiated, this endpoint is the receiver
    /// only, and a RESET_STREAM on a send-only stream is a STREAM_STATE_ERROR
    /// (RFC 9000 section 19.4).
    public var hasSendHalf: Bool {
        quicStream.hasSendHalf
    }

    /// Whether this endpoint owns the stream's receive half (RFC 9000 section 2.1).
    ///
    /// The mirror of ``hasSendHalf``, guarding STOP_SENDING: RFC 9000 section
    /// 19.5 makes a STOP_SENDING frame for a receive-only stream a
    /// STREAM_STATE_ERROR.
    public var hasReceiveHalf: Bool {
        quicStream.hasReceiveHalf
    }

    public mutating func reset(applicationErrorCode: UInt64) -> QUICFrame {
        _ = quicStream.reset(applicationErrorCode: applicationErrorCode)
        return .resetStreamAt(
            id: streamID,
            applicationErrorCode: applicationErrorCode,
            finalSize: quicStream.sendOffset,
            reliableSize: quicStream.sendOffset
        )
    }

    public mutating func stopSending(applicationErrorCode: UInt64) -> QUICFrame {
        quicStream.stopSending(applicationErrorCode: applicationErrorCode)
    }
}
