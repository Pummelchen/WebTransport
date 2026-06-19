import Foundation
import WebTransportQUICCore

public enum WebTransportDraft15ErrorKind: Equatable, Sendable {
    case bufferedStreamRejected
    case sessionGone
    case flowControl
    case alpn
    case requirementsNotMet
    case h3ID
}

public struct WebTransportDraft15Error: Error, Equatable, Sendable {
    public let kind: WebTransportDraft15ErrorKind
    public let message: String

    public init(kind: WebTransportDraft15ErrorKind, message: String) {
        self.kind = kind
        self.message = message
    }

    public var code: UInt64 {
        WebTransportDraft15ErrorMapper.code(for: kind)
    }
}

public enum WebTransportDraft15ErrorMapper {
    public static func code(
        for kind: WebTransportDraft15ErrorKind,
        constants: WebTransportHTTP3DraftConstants = .current
    ) -> UInt64 {
        switch kind {
        case .bufferedStreamRejected:
            return constants.wtBufferedStreamRejectedError
        case .sessionGone:
            return constants.wtSessionGoneError
        case .flowControl:
            return constants.wtFlowControlError
        case .alpn:
            return constants.wtALPNError
        case .requirementsNotMet:
            return constants.wtRequirementsNotMetError
        case .h3ID:
            return HTTP3ApplicationErrorCode.idError.rawValue
        }
    }

    public static func connectionCloseFrame(
        for kind: WebTransportDraft15ErrorKind,
        reason: String
    ) -> QUICFrame {
        .connectionClose(
            errorCode: code(for: kind),
            frameType: nil,
            reason: Data(reason.utf8)
        )
    }
}
