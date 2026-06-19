import Foundation
import WebTransportQUICCore

public struct WebTransportDatagramPrefix: Equatable, Sendable {
    public let sessionID: WebTransportSessionID
    public let bytesConsumed: Int
    public let payload: Data

    public init(sessionID: WebTransportSessionID, bytesConsumed: Int, payload: Data) {
        self.sessionID = sessionID
        self.bytesConsumed = bytesConsumed
        self.payload = payload
    }
}

public enum WebTransportDatagramSignaling {
    public static func serialize(sessionID: UInt64, payload: Data) throws -> Data {
        var output = Data()
        output.append(try QUICVarInt.encode(sessionID))
        output.append(payload)
        return output
    }

    public static func parse(_ bytes: Data) throws -> WebTransportDatagramPrefix {
        var cursor = QUICByteCursor(bytes)
        let sessionRaw = try QUICVarInt.decode(from: &cursor)
        let sessionID = try WebTransportSessionID.fromRequestStreamID(sessionRaw)
        let bytesConsumed = cursor.offset - bytes.startIndex
        let payload = try cursor.readBytes(count: cursor.remaining)
        return WebTransportDatagramPrefix(
            sessionID: sessionID,
            bytesConsumed: bytesConsumed,
            payload: payload
        )
    }
}
