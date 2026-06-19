import Foundation
import WebTransportQUICCore

public struct WebTransportDatagramPrefix: Equatable, Sendable {
    public let sessionID: WebTransportSessionID
    public let quarterStreamID: UInt64
    public let bytesConsumed: Int
    public let payload: Data

    public init(sessionID: WebTransportSessionID, quarterStreamID: UInt64, bytesConsumed: Int, payload: Data) {
        self.sessionID = sessionID
        self.quarterStreamID = quarterStreamID
        self.bytesConsumed = bytesConsumed
        self.payload = payload
    }
}

public enum WebTransportDatagramSignaling {
    public static func serialize(sessionID: UInt64, payload: Data) throws -> Data {
        var output = Data()
        output.append(try QUICVarInt.encode(try quarterStreamID(for: WebTransportSessionID(rawValue: sessionID))))
        output.append(payload)
        return output
    }

    public static func parse(_ bytes: Data) throws -> WebTransportDatagramPrefix {
        var cursor = QUICByteCursor(bytes)
        let quarterStreamID = try QUICVarInt.decode(from: &cursor)
        let sessionID = try sessionID(fromQuarterStreamID: quarterStreamID)
        let bytesConsumed = cursor.offset - bytes.startIndex
        let payload = try cursor.readBytes(count: cursor.remaining)
        return WebTransportDatagramPrefix(
            sessionID: sessionID,
            quarterStreamID: quarterStreamID,
            bytesConsumed: bytesConsumed,
            payload: payload
        )
    }

    public static func quarterStreamID(for sessionID: WebTransportSessionID) throws -> UInt64 {
        guard sessionID.rawValue.isMultiple(of: 4) else {
            throw QUICCodecError.malformed("WebTransport datagram session ID must be a client-initiated bidirectional stream ID")
        }
        return sessionID.rawValue / 4
    }

    public static func sessionID(fromQuarterStreamID quarterStreamID: UInt64) throws -> WebTransportSessionID {
        guard quarterStreamID <= UInt64.max / 4 else {
            throw QUICCodecError.valueOutOfRange("WebTransport datagram quarter stream ID overflows request stream ID")
        }
        return try WebTransportSessionID.fromRequestStreamID(quarterStreamID * 4)
    }
}
