import Foundation
import WebTransportQUICCore

/// The manager's read-only surface: the payload queues and stream registries an embedder inspects,
/// and the one builder that does not touch session state.
extension WebTransportSessionManager {
    public func datagramQueue(sessionID: WebTransportSessionID) -> [Data]? {
        datagramsBySessionID[sessionID]
    }

    public func bufferedStreamIDs(for sessionID: WebTransportSessionID) -> Set<UInt64>? {
        bufferedStreamIDsBySessionID[sessionID]
    }

    public func flowState(for sessionID: WebTransportSessionID) -> WebTransportFlowControlState? {
        flowControlStateBySessionID[sessionID]
    }

    public func receiveFlowState(for sessionID: WebTransportSessionID) -> WebTransportFlowControlState? {
        receiveFlowControlStateBySessionID[sessionID]
    }

    public func makeOptimisticConnectStreamCapsule(
        sessionID: WebTransportSessionID,
        capsule: WebTransportFlowCapsule
    ) throws -> Data {
        guard http3.role == .client else {
            throw QUICCodecError.malformed("only clients send optimistic WebTransport capsules")
        }
        guard sessionsByID[sessionID]?.state == .requested else {
            throw QUICCodecError.malformed("optimistic WebTransport capsules require a pending CONNECT request")
        }
        return try WebTransportFlowCapsuleCodec.serialize(capsule)
    }

    public func stream(for streamID: UInt64) -> WebTransportStreamState? {
        streamsByID[streamID]
    }

    public func streamIDs(for sessionID: WebTransportSessionID) -> Set<UInt64>? {
        streamIDsBySessionID[sessionID]
    }

    public func session(forRequestStreamID streamID: UInt64) -> WebTransportSession? {
        guard let sessionID = sessionIDsByRequestStreamID[streamID] else {
            return nil
        }
        return sessionsByID[sessionID]
    }
}
