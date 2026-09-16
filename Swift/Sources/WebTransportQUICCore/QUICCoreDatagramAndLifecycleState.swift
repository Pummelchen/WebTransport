import Foundation

public struct QUICCongestionController: Equatable, Sendable {
    public let maxDatagramSize: UInt64
    public let minimumWindow: UInt64
    public private(set) var congestionWindow: UInt64
    public private(set) var bytesInFlight: UInt64

    public init(maxDatagramSize: UInt64 = 1_200) {
        self.maxDatagramSize = maxDatagramSize
        self.minimumWindow = maxDatagramSize * 2
        self.congestionWindow = max(maxDatagramSize * 10, 14_720)
        self.bytesInFlight = 0
    }

    public func canSend(bytes: UInt64) -> Bool {
        let (attempted, overflow) = bytesInFlight.addingReportingOverflow(bytes)
        return !overflow && attempted <= congestionWindow
    }

    public mutating func onPacketSent(bytes: UInt64, ackEliciting: Bool = true) {
        guard ackEliciting else {
            return
        }
        let (newBytesInFlight, overflow) = bytesInFlight.addingReportingOverflow(bytes)
        bytesInFlight = overflow ? UInt64.max : newBytesInFlight
    }

    public mutating func onPacketAcknowledged(bytes: UInt64) {
        bytesInFlight = bytes > bytesInFlight ? 0 : bytesInFlight - bytes
        let (newWindow, overflow) = congestionWindow.addingReportingOverflow(min(bytes, maxDatagramSize))
        congestionWindow = overflow ? UInt64.max : newWindow
    }

    public mutating func onPacketsLost(bytes: UInt64) {
        bytesInFlight = bytes > bytesInFlight ? 0 : bytesInFlight - bytes
        congestionWindow = max(congestionWindow / 2, minimumWindow)
    }
}

public enum QUICTransportErrorCode: UInt64, Equatable, Sendable {
    case noError = 0x00
    case internalError = 0x01
    case connectionRefused = 0x02
    case flowControlError = 0x03
    case streamLimitError = 0x04
    case streamStateError = 0x05
    case finalSizeError = 0x06
    case frameEncodingError = 0x07
    case transportParameterError = 0x08
    case connectionIDLimitError = 0x09
    case protocolViolation = 0x0a
    case invalidToken = 0x0b
    case applicationError = 0x0c
    case cryptoBufferExceeded = 0x0d
    case keyUpdateError = 0x0e
    case aeadLimitReached = 0x0f
    case noViablePath = 0x10
}

public struct QUICConnectionCloseState: Equatable, Sendable {
    public var idleTimeoutMicros: UInt64
    public private(set) var lastActivityMicros: UInt64
    public private(set) var closeFrame: QUICFrame?

    public init(idleTimeoutMicros: UInt64, nowMicros: UInt64 = 0) {
        self.idleTimeoutMicros = idleTimeoutMicros
        self.lastActivityMicros = nowMicros
        self.closeFrame = nil
    }

    public var isClosed: Bool {
        closeFrame != nil
    }

    public mutating func recordActivity(nowMicros: UInt64) throws {
        guard closeFrame == nil else {
            throw QUICStateError.connectionClosed
        }
        lastActivityMicros = nowMicros
    }

    public mutating func checkIdleTimeout(nowMicros: UInt64) throws -> Bool {
        guard closeFrame == nil else {
            throw QUICStateError.connectionClosed
        }
        guard nowMicros >= lastActivityMicros else {
            return false
        }
        if nowMicros - lastActivityMicros >= idleTimeoutMicros {
            closeFrame = .connectionClose(
                errorCode: QUICTransportErrorCode.noError.rawValue,
                frameType: nil,
                reason: Data("idle timeout".utf8)
            )
            return true
        }
        return false
    }

    public mutating func closeTransport(
        error: QUICTransportErrorCode,
        frameType: UInt64?,
        reason: String
    ) -> QUICFrame {
        let frame = QUICFrame.connectionClose(
            errorCode: error.rawValue,
            frameType: frameType,
            reason: Data(reason.utf8)
        )
        closeFrame = frame
        return frame
    }

    public mutating func closeApplication(errorCode: UInt64, reason: String) -> QUICFrame {
        let frame = QUICFrame.connectionClose(
            errorCode: errorCode,
            frameType: nil,
            reason: Data(reason.utf8)
        )
        closeFrame = frame
        return frame
    }
}
