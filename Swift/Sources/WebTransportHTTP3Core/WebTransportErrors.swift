import Foundation
import WebTransportQUICCore

public enum WebTransportDraft16ErrorKind: Equatable, Sendable {
    case bufferedStreamRejected
    case sessionGone
    case flowControl
    case alpn
    case requirementsNotMet
    case h3ID
    case requestRejected
}

public struct WebTransportDraft16Error: Error, Equatable, Sendable {
    public let kind: WebTransportDraft16ErrorKind
    public let message: String

    public init(kind: WebTransportDraft16ErrorKind, message: String) {
        self.kind = kind
        self.message = message
    }

    public var code: UInt64 {
        WebTransportDraft16ErrorMapper.code(for: kind)
    }
}

public enum WebTransportDraft16StreamSignal: Equatable, Sendable {
    case resetStream(streamID: UInt64, finalSize: UInt64)
    case stopSending(streamID: UInt64)
}

public enum WebTransportDraft16ErrorMapper {
    public static func httpErrorCode(forApplicationErrorCode code: UInt32) -> UInt64 {
        let first = WebTransportHTTP3DraftConstants.current.wtApplicationErrorRange.lowerBound
        return first + UInt64(code) + (UInt64(code) / 0x1e)
    }

    public static func applicationErrorCode(forHTTPErrorCode code: UInt64) throws -> UInt32 {
        let range = WebTransportHTTP3DraftConstants.current.wtApplicationErrorRange
        guard range.contains(code), !HTTP3FrameType.isReserved(code) else {
            throw QUICCodecError.valueOutOfRange("HTTP/3 error code is not a WebTransport application error")
        }
        let shifted = code - range.lowerBound
        let applicationCode = shifted - (shifted / 0x1f)
        guard applicationCode <= UInt64(UInt32.max) else {
            throw QUICCodecError.valueOutOfRange("mapped WebTransport application error exceeds UInt32")
        }
        return UInt32(applicationCode)
    }

    public static func code(
        for kind: WebTransportDraft16ErrorKind,
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
        case .requestRejected:
            return HTTP3ApplicationErrorCode.requestRejected.rawValue
        }
    }

    public static func connectionCloseFrame(
        for kind: WebTransportDraft16ErrorKind,
        reason: String
    ) -> QUICFrame {
        .connectionClose(
            errorCode: code(for: kind),
            frameType: nil,
            reason: Data(reason.utf8)
        )
    }

    public static func streamFrame(
        for kind: WebTransportDraft16ErrorKind,
        signal: WebTransportDraft16StreamSignal
    ) -> QUICFrame {
        switch signal {
        case .resetStream(let streamID, let finalSize):
            return .resetStream(id: streamID, applicationErrorCode: code(for: kind), finalSize: finalSize)
        case .stopSending(let streamID):
            return .stopSending(id: streamID, applicationErrorCode: code(for: kind))
        }
    }

    public static func closeSessionCapsule(
        for kind: WebTransportDraft16ErrorKind,
        message: String
    ) throws -> Data {
        let errorCode = code(for: kind)
        guard errorCode <= UInt64(UInt32.max) else {
            throw QUICCodecError.valueOutOfRange("WebTransport close-session error code exceeds UInt32")
        }
        return try WebTransportFlowCapsuleCodec.serialize(.closeSession(
            applicationErrorCode: UInt32(errorCode),
            message: message
        ))
    }
}

@available(*, deprecated, renamed: "WebTransportDraft16ErrorKind")
public typealias WebTransportDraft15ErrorKind = WebTransportDraft16ErrorKind

@available(*, deprecated, renamed: "WebTransportDraft16Error")
public typealias WebTransportDraft15Error = WebTransportDraft16Error

@available(*, deprecated, renamed: "WebTransportDraft16StreamSignal")
public typealias WebTransportDraft15StreamSignal = WebTransportDraft16StreamSignal

@available(*, deprecated, renamed: "WebTransportDraft16ErrorMapper")
public typealias WebTransportDraft15ErrorMapper = WebTransportDraft16ErrorMapper
