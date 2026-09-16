import Foundation
import WebTransportQUICCore

/// ``WebTransportSessionManager``'s datagram delivery: the send-side size ceiling, the receive-side
/// buffering and its byte accounting, and the queue pop an embedder reads.
extension WebTransportSessionManager {
    public mutating func makeDatagramFrame(
        sessionID: WebTransportSessionID,
        payload: Data
    ) throws -> QUICFrame {
        try validateSettingsReady()
        _ = try writableSession(for: sessionID)

        let datagramPayload = try WebTransportDatagramSignaling.serialize(
            sessionID: sessionID.rawValue,
            payload: payload
        )
        guard datagramPayload.count <= maxSendableDatagramFrameSize else {
            throw QUICCodecError.valueOutOfRange(
                "WebTransport datagram payload exceeds the sendable frame size of \(maxSendableDatagramFrameSize)"
            )
        }
        return .datagram(datagramPayload)
    }

    public mutating func receiveDatagramFrame(_ frame: QUICFrame) throws -> WebTransportSessionID {
        try validateSettingsReady()
        guard case .datagram(let payload) = frame else {
            throw QUICCodecError.malformed("expected DATAGRAM frame")
        }
        guard payload.count <= maxDatagramFrameSize else {
            throw QUICCodecError.valueOutOfRange(
                "WebTransport datagram payload exceeds maximum frame size of \(maxDatagramFrameSize)"
            )
        }
        let parsed: WebTransportDatagramPrefix
        do {
            parsed = try WebTransportDatagramSignaling.parse(payload)
        } catch {
            throw WebTransportDraft16Error(kind: .h3ID, message: "invalid WebTransport datagram session ID")
        }
        let session = try sessionForIngressOrPending(parsed.sessionID)
        let currentBytes = datagramPayloadBytesBySessionID[parsed.sessionID] ?? 0
        let updatedBytes = currentBytes + parsed.payload.count
        guard updatedBytes <= maxDatagramReceiveBufferBytes else {
            if session == nil || session?.state == .requested {
                return parsed.sessionID
            }
            throw QUICCodecError.valueOutOfRange("WebTransport datagram receive buffer limit exceeded")
        }

        var queue = datagramsBySessionID[parsed.sessionID] ?? []
        if session?.state != .accepted && session?.state != .draining {
            try ensureCanBufferIngress(for: parsed.sessionID)
            guard queue.count < maxBufferedDatagramsPerSession else {
                return parsed.sessionID
            }
        }
        queue.append(parsed.payload)
        datagramsBySessionID[parsed.sessionID] = queue
        datagramPayloadBytesBySessionID[parsed.sessionID] = updatedBytes
        return parsed.sessionID
    }

    public mutating func popDatagramPayload(sessionID: WebTransportSessionID) -> Data? {
        guard var queue = datagramsBySessionID[sessionID] else {
            return nil
        }
        guard let payload = queue.first else {
            return nil
        }
        queue.removeFirst()
        datagramsBySessionID[sessionID] = queue.isEmpty ? [] : queue

        let currentBytes = datagramPayloadBytesBySessionID[sessionID] ?? 0
        datagramPayloadBytesBySessionID[sessionID] = max(0, currentBytes - payload.count)
        return payload
    }
}
