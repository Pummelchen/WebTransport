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
            throw WebTransportDraft15Error(
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
    public private(set) var bufferedPayloads: [Data]
    public private(set) var bufferedPayloadBytes: Int
    public let maxBufferedBytes: Int

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
        self.bufferedPayloads = []
        self.bufferedPayloadBytes = 0
        self.maxBufferedBytes = maxBufferedBytes
    }

    public mutating func receivePayload(_ data: Data) throws {
        guard data.count <= max(0, maxBufferedBytes - bufferedPayloadBytes) else {
            throw QUICCodecError.malformed("WebTransport stream receive buffer limit exceeded")
        }

        let frame = QUICFrame.stream(id: streamID, offset: quicStream.receiveOffset, fin: false, data: data)
        _ = try quicStream.receive(frame)
        bufferedPayloads.append(data)
        bufferedPayloadBytes += data.count
    }

    public mutating func popPayload() -> Data? {
        guard let first = bufferedPayloads.first else {
            return nil
        }
        bufferedPayloads.removeFirst()
        bufferedPayloadBytes -= first.count
        return first
    }

    public mutating func reset(applicationErrorCode: UInt64) -> QUICFrame {
        quicStream.reset(applicationErrorCode: applicationErrorCode)
    }

    public mutating func stopSending(applicationErrorCode: UInt64) -> QUICFrame {
        quicStream.stopSending(applicationErrorCode: applicationErrorCode)
    }
}
