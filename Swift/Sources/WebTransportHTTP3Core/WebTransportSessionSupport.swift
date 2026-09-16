import Foundation
import WebTransportQUICCore

/// Read-only support for ``WebTransportSessionManager``: the session lookup and admission checks
/// every protocol path calls, and the file-scope capsule and frame helpers.
///
/// These members are `internal` rather than `private` because `WebTransportSessionManager` is
/// declared across several files, and `private` does not cross a file boundary.
extension WebTransportSessionManager {
    func writableSession(for sessionID: WebTransportSessionID) throws -> WebTransportSession {
        guard let session = sessionsByID[sessionID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        switch session.state {
        case .accepted, .draining:
            return session
        case .closed:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        case .requested:
            throw QUICCodecError.malformed("WebTransport session is not accepted")
        }
    }

    func sessionForIngress(_ sessionID: WebTransportSessionID) throws -> WebTransportSession {
        guard let session = sessionsByID[sessionID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        switch session.state {
        case .requested, .accepted, .draining:
            return session
        case .closed:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        }
    }

    func sessionForIngressOrPending(_ sessionID: WebTransportSessionID) throws -> WebTransportSession? {
        guard let session = sessionsByID[sessionID] else {
            if http3.role == .server {
                return nil
            }
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        switch session.state {
        case .requested, .accepted, .draining:
            return session
        case .closed:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        }
    }

    func validateSettingsReady() throws {
        switch settingsValidation {
        case .draft16Strict:
            try http3.localSettings.validateWebTransportDraft16Requirements()
        case .interoperable, .chromiumInterop:
            try http3.localSettings.validateWebTransportChromiumInteropRequirements()
        case .pywebtransportStreamInterop:
            try http3.localSettings.validateWebTransportPyWebTransportStreamInteropRequirements()
        }
        guard let remoteSettings = http3.remoteSettings else {
            throw QUICCodecError.malformed("peer HTTP/3 SETTINGS are required before WebTransport session establishment")
        }
        let peerRole: HTTP3ConnectionRole = http3.role == .client ? .server : .client
        switch settingsValidation {
        case .draft16Strict:
            try remoteSettings.validateWebTransportDraft16Requirements(peerRole: peerRole)
        case .interoperable, .chromiumInterop:
            try remoteSettings.validateWebTransportChromiumInteropRequirements(peerRole: peerRole)
        case .pywebtransportStreamInterop:
            try remoteSettings.validateWebTransportPyWebTransportStreamInteropRequirements(peerRole: peerRole)
        }
    }

    /// Refuses a second concurrent session unless WebTransport flow control was
    /// negotiated with the peer.
    ///
    /// The gate is deliberate and load-bearing: a connection with more than one
    /// WebTransport session can only demultiplex them if both endpoints exchange
    /// the `SETTINGS_WT_INITIAL_MAX_*` limits, so this endpoint refuses the
    /// second session rather than admitting traffic it cannot account for. The
    /// shipped `WebTransportNetworkRuntime` never advertises those settings, so
    /// this always refuses there and one session per connection is the effective
    /// contract; the limit is lifted only for embedders that drive
    /// ``WebTransportSessionManager`` directly and negotiate flow control
    /// themselves (as the conformance suite does).
    func validateSessionAdmission() throws {
        guard !webTransportFlowControlNegotiated else {
            return
        }
        let activeCount = sessionsByID.values.filter { session in
            switch session.state {
            case .requested, .accepted, .draining:
                return true
            case .closed, .rejected:
                return false
            }
        }.count
        guard activeCount == 0 else {
            throw WebTransportDraft16Error(
                kind: http3.role == .server ? .requestRejected : .requirementsNotMet,
                message: "multiple simultaneous WebTransport sessions require WebTransport flow control"
            )
        }
    }

    var webTransportFlowControlNegotiated: Bool {
        guard let remoteSettings = http3.remoteSettings else {
            return false
        }
        return http3.localSettings.webTransportFlowControlEnabled(with: remoteSettings)
    }

    func validateRequestAllowedByGoaway(_ streamID: UInt64) throws {
        guard let goawayID = http3.receivedGoawayID else {
            return
        }
        guard streamID < goawayID else {
            throw WebTransportDraft16Error(
                kind: .sessionGone,
                message: "new WebTransport session is blocked by GOAWAY"
            )
        }
    }
}

func capsuleTypePrefix(_ bytes: Data) throws -> UInt64 {
    var cursor = QUICByteCursor(bytes)
    return try QUICVarInt.decode(from: &cursor)
}

func isHTTP3FlowControlCapsuleType(_ type: UInt64) -> Bool {
    let constants = WebTransportHTTP3DraftConstants.current
    return type == constants.wtMaxDataCapsule
        || type == constants.wtMaxStreamsBidiCapsule
        || type == constants.wtMaxStreamsUniCapsule
        || type == constants.wtDataBlockedCapsule
        || type == constants.wtStreamsBlockedBidiCapsule
        || type == constants.wtStreamsBlockedUniCapsule
}

func ignoredFlowControlCapsuleEnvelope(_ bytes: Data) throws -> WebTransportFlowCapsuleEnvelope {
    var cursor = QUICByteCursor(bytes)
    let type = try QUICVarInt.decode(from: &cursor)
    let payloadLength = try QUICVarInt.decode(from: &cursor)
    guard payloadLength <= UInt64(Int.max) else {
        throw QUICCodecError.valueOutOfRange("flow control capsule payload length exceeds Int.max")
    }
    let payload = try cursor.readBytes(count: Int(payloadLength))
    return WebTransportFlowCapsuleEnvelope(
        capsule: .unknown(type: type, payload: payload),
        bytesConsumed: bytes.count - cursor.remaining,
        payload: payload
    )
}

func connectMessageErrorReset(streamID: UInt64) -> QUICFrame {
    .resetStream(
        id: streamID,
        applicationErrorCode: HTTP3ApplicationErrorCode.messageError.rawValue,
        finalSize: 0
    )
}

func bufferedStreamRejectedFrame(streamID: UInt64) -> QUICFrame {
    .resetStreamAt(
        id: streamID,
        applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError,
        finalSize: 0,
        reliableSize: 0
    )
}
