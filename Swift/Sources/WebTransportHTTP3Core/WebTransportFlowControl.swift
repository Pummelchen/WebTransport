import Foundation
import WebTransportQUICCore

public enum WebTransportFlowCapsule: Equatable, Sendable {
    case drainSession
    case closeSession(applicationErrorCode: UInt32, message: String)
    case maxData(limit: UInt64)
    case maxStreamsBidi(limit: UInt64)
    case maxStreamsUni(limit: UInt64)
    case dataBlocked(limit: UInt64)
    case streamsBlockedBidi(limit: UInt64)
    case streamsBlockedUni(limit: UInt64)
    case unknown(type: UInt64, payload: Data)
}

public struct WebTransportFlowCapsuleEnvelope: Equatable, Sendable {
    public let capsule: WebTransportFlowCapsule
    public let bytesConsumed: Int
    public let payload: Data

    public init(capsule: WebTransportFlowCapsule, bytesConsumed: Int, payload: Data) {
        self.capsule = capsule
        self.bytesConsumed = bytesConsumed
        self.payload = payload
    }
}

public enum WebTransportFlowCapsuleCodec {
    public static func serialize(_ capsule: WebTransportFlowCapsule) throws -> Data {
        var output = Data()
        let (type, payload) = try serializedTypeAndPayload(capsule)
        output.append(try QUICVarInt.encode(type))
        output.append(try QUICVarInt.encode(UInt64(payload.count)))
        output.append(payload)
        return output
    }

    public static func parse(
        _ bytes: Data,
        constants: WebTransportHTTP3DraftConstants = .current
    ) throws -> WebTransportFlowCapsuleEnvelope {
        var cursor = QUICByteCursor(bytes)
        let type = try QUICVarInt.decode(from: &cursor)
        let payloadLength = try QUICVarInt.decode(from: &cursor)
        guard payloadLength <= UInt64(Int.max) else {
            throw QUICCodecError.valueOutOfRange("flow control capsule payload length exceeds Int.max")
        }
        let length = Int(payloadLength)
        let payload = try cursor.readBytes(count: length)
        let bytesConsumed = bytes.count - cursor.remaining

        var payloadCursor = QUICByteCursor(payload)
        let capsule: WebTransportFlowCapsule

        switch type {
        case constants.wtDrainSessionCapsule:
            guard payload.isEmpty else {
                throw QUICCodecError.malformed("WT_DRAIN_SESSION capsule must have an empty payload")
            }
            capsule = .drainSession
            return WebTransportFlowCapsuleEnvelope(capsule: capsule, bytesConsumed: bytesConsumed, payload: payload)
        case constants.wtCloseSessionCapsule:
            capsule = try parseCloseSession(payload)
            return WebTransportFlowCapsuleEnvelope(capsule: capsule, bytesConsumed: bytesConsumed, payload: payload)
        case constants.wtMaxDataCapsule:
            let limit = try readSingleVarInt(
                from: &payloadCursor,
                label: "wt-max-data"
            )
            capsule = .maxData(limit: limit)
        case constants.wtMaxStreamsBidiCapsule:
            let limit = try readSingleVarInt(
                from: &payloadCursor,
                label: "wt-max-streams-bidi"
            )
            capsule = .maxStreamsBidi(limit: limit)
        case constants.wtMaxStreamsUniCapsule:
            let limit = try readSingleVarInt(
                from: &payloadCursor,
                label: "wt-max-streams-uni"
            )
            capsule = .maxStreamsUni(limit: limit)
        case constants.wtDataBlockedCapsule:
            let limit = try readSingleVarInt(
                from: &payloadCursor,
                label: "wt-data-blocked"
            )
            capsule = .dataBlocked(limit: limit)
        case constants.wtStreamsBlockedBidiCapsule:
            let limit = try readSingleVarInt(
                from: &payloadCursor,
                label: "wt-streams-blocked-bidi"
            )
            capsule = .streamsBlockedBidi(limit: limit)
        case constants.wtStreamsBlockedUniCapsule:
            let limit = try readSingleVarInt(
                from: &payloadCursor,
                label: "wt-streams-blocked-uni"
            )
            capsule = .streamsBlockedUni(limit: limit)
        default:
            capsule = .unknown(type: type, payload: payload)
            return WebTransportFlowCapsuleEnvelope(capsule: capsule, bytesConsumed: bytesConsumed, payload: payload)
        }

        if !payloadCursor.isAtEnd {
            throw QUICCodecError.malformed("flow control capsule payload contains extra bytes")
        }

        return WebTransportFlowCapsuleEnvelope(capsule: capsule, bytesConsumed: bytesConsumed, payload: payload)
    }

    public static func serializedTypeAndPayload(_ capsule: WebTransportFlowCapsule) throws -> (UInt64, Data) {
        switch capsule {
        case .drainSession:
            return (WebTransportHTTP3DraftConstants.current.wtDrainSessionCapsule, Data())
        case .closeSession(let applicationErrorCode, let message):
            let messageBytes = Data(message.utf8)
            guard messageBytes.count <= WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes else {
                throw QUICCodecError.valueOutOfRange("WT_CLOSE_SESSION message exceeds \(WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes) bytes")
            }
            var payload = Data()
            payload.append(UInt8((applicationErrorCode >> 24) & 0xff))
            payload.append(UInt8((applicationErrorCode >> 16) & 0xff))
            payload.append(UInt8((applicationErrorCode >> 8) & 0xff))
            payload.append(UInt8(applicationErrorCode & 0xff))
            payload.append(messageBytes)
            return (WebTransportHTTP3DraftConstants.current.wtCloseSessionCapsule, payload)
        case .maxData(let limit):
            return (WebTransportHTTP3DraftConstants.current.wtMaxDataCapsule, try encodePayload(limit: limit))
        case .maxStreamsBidi(let limit):
            return (WebTransportHTTP3DraftConstants.current.wtMaxStreamsBidiCapsule, try encodePayload(limit: limit))
        case .maxStreamsUni(let limit):
            return (WebTransportHTTP3DraftConstants.current.wtMaxStreamsUniCapsule, try encodePayload(limit: limit))
        case .dataBlocked(let limit):
            return (WebTransportHTTP3DraftConstants.current.wtDataBlockedCapsule, try encodePayload(limit: limit))
        case .streamsBlockedBidi(let limit):
            return (WebTransportHTTP3DraftConstants.current.wtStreamsBlockedBidiCapsule, try encodePayload(limit: limit))
        case .streamsBlockedUni(let limit):
            return (WebTransportHTTP3DraftConstants.current.wtStreamsBlockedUniCapsule, try encodePayload(limit: limit))
        case .unknown(let type, let payload):
            return (type, payload)
        }
    }

    private static func encodePayload(limit: UInt64) throws -> Data {
        var payload = Data()
        payload.append(try QUICVarInt.encode(limit))
        return payload
    }

    private static func parseCloseSession(_ payload: Data) throws -> WebTransportFlowCapsule {
        guard payload.count >= 4 else {
            throw QUICCodecError.malformed("WT_CLOSE_SESSION capsule payload is shorter than 32-bit error code")
        }
        let bytes = [UInt8](payload.prefix(4))
        let errorCode = UInt32(bytes[0]) << 24
            | UInt32(bytes[1]) << 16
            | UInt32(bytes[2]) << 8
            | UInt32(bytes[3])
        let messageBytes = payload.dropFirst(4)
        guard messageBytes.count <= WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes else {
            throw QUICCodecError.valueOutOfRange("WT_CLOSE_SESSION message exceeds \(WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes) bytes")
        }
        guard let message = String(data: Data(messageBytes), encoding: .utf8) else {
            throw QUICCodecError.malformed("WT_CLOSE_SESSION message must be UTF-8")
        }
        return .closeSession(applicationErrorCode: errorCode, message: message)
    }

    private static func readSingleVarInt(
        from cursor: inout QUICByteCursor,
        label: String
    ) throws -> UInt64 {
        guard !cursor.isAtEnd else {
            throw QUICCodecError.malformed("flow control capsule has empty payload for \(label)")
        }
        let value = try QUICVarInt.decode(from: &cursor)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("flow control capsule payload has trailing bytes for \(label)")
        }
        if label == "wt-max-streams-bidi" || label == "wt-max-streams-uni" {
            guard value <= WebTransportHTTP3DraftConstants.current.maximumMaxStreamsValue else {
                throw QUICCodecError.valueOutOfRange("\(label) exceeds the draft-15 2^60 maximum")
            }
        }
        return value
    }
}

public enum WebTransportFlowControlLimitState: Equatable, Sendable {
    case disabled
    case zero
    case unlimited
    case limited(UInt64)

    public var numericValue: UInt64? {
        switch self {
        case .zero:
            return 0
        case .limited(let value):
            return value
        case .disabled, .unlimited:
            return nil
        }
    }
}

private extension WebTransportFlowControlLimitState {
    init(_ limit: UInt64?, isEnabled: Bool) {
        guard isEnabled else {
            self = .disabled
            return
        }
        guard let limit else {
            self = .unlimited
            return
        }
        self = limit == 0 ? .zero : .limited(limit)
    }

    var asUInt64: UInt64? {
        switch self {
        case .zero:
            return 0
        case .limited(let value):
            return value
        case .disabled, .unlimited:
            return nil
        }
    }

}

extension WebTransportHTTP3DraftConstants {
    public var maximumMaxStreamsValue: UInt64 {
        1 << 60
    }
}

extension HTTP3Settings {
    public func webTransportFlowControlEnabled(
        constants: WebTransportHTTP3DraftConstants = .current
    ) -> Bool {
        entries.keys.contains(constants.settingsWTInitialMaxData)
            || entries.keys.contains(constants.settingsWTInitialMaxStreamsBidi)
            || entries.keys.contains(constants.settingsWTInitialMaxStreamsUni)
    }
}

public struct WebTransportFlowControlState: Equatable, Sendable {
    public private(set) var isEnabled: Bool
    public private(set) var maxDataState: WebTransportFlowControlLimitState
    public private(set) var maxStreamsBidiState: WebTransportFlowControlLimitState
    public private(set) var maxStreamsUniState: WebTransportFlowControlLimitState
    public private(set) var usedData: UInt64
    public private(set) var openedBidiStreams: Int
    public private(set) var openedUniStreams: Int

    public var maxData: UInt64? {
        maxDataState.asUInt64
    }

    public var maxStreamsBidi: UInt64? {
        maxStreamsBidiState.asUInt64
    }

    public var maxStreamsUni: UInt64? {
        maxStreamsUniState.asUInt64
    }

    public init(
        maxData: UInt64?,
        maxStreamsBidi: UInt64?,
        maxStreamsUni: UInt64?,
        isEnabled: Bool = true
    ) {
        self.isEnabled = isEnabled
        self.maxDataState = WebTransportFlowControlLimitState(maxData, isEnabled: isEnabled)
        self.maxStreamsBidiState = WebTransportFlowControlLimitState(maxStreamsBidi, isEnabled: isEnabled)
        self.maxStreamsUniState = WebTransportFlowControlLimitState(maxStreamsUni, isEnabled: isEnabled)
        self.usedData = 0
        self.openedBidiStreams = 0
        self.openedUniStreams = 0
    }

    public init(settings: HTTP3Settings, constants: WebTransportHTTP3DraftConstants = .current) {
        self.isEnabled = settings.webTransportFlowControlEnabled(constants: constants)
        self.maxDataState = WebTransportFlowControlLimitState(settings[constants.settingsWTInitialMaxData], isEnabled: isEnabled)
        self.maxStreamsBidiState = WebTransportFlowControlLimitState(settings[constants.settingsWTInitialMaxStreamsBidi], isEnabled: isEnabled)
        self.maxStreamsUniState = WebTransportFlowControlLimitState(settings[constants.settingsWTInitialMaxStreamsUni], isEnabled: isEnabled)
        self.usedData = 0
        self.openedBidiStreams = 0
        self.openedUniStreams = 0
    }

    public init() {
        self.init(maxData: nil, maxStreamsBidi: nil, maxStreamsUni: nil, isEnabled: false)
    }

    public mutating func setMaxData(_ value: UInt64) throws {
        guard isEnabled else { return }
        try setMonotonicLimit(&maxDataState, value: value, label: "WT_MAX_DATA")
    }

    public mutating func setMaxStreamsBidi(_ value: UInt64) throws {
        guard isEnabled else { return }
        guard value <= WebTransportHTTP3DraftConstants.current.maximumMaxStreamsValue else {
            throw QUICCodecError.valueOutOfRange("WT_MAX_STREAMS_BIDI exceeds the draft-15 2^60 maximum")
        }
        try setMonotonicLimit(&maxStreamsBidiState, value: value, label: "WT_MAX_STREAMS_BIDI")
    }

    public mutating func setMaxStreamsUni(_ value: UInt64) throws {
        guard isEnabled else { return }
        guard value <= WebTransportHTTP3DraftConstants.current.maximumMaxStreamsValue else {
            throw QUICCodecError.valueOutOfRange("WT_MAX_STREAMS_UNI exceeds the draft-15 2^60 maximum")
        }
        try setMonotonicLimit(&maxStreamsUniState, value: value, label: "WT_MAX_STREAMS_UNI")
    }

    public mutating func apply(_ capsule: WebTransportFlowCapsule) throws {
        switch capsule {
        case .maxData(let limit):
            try setMaxData(limit)
        case .maxStreamsBidi(let limit):
            try setMaxStreamsBidi(limit)
        case .maxStreamsUni(let limit):
            try setMaxStreamsUni(limit)
        case .drainSession, .closeSession, .dataBlocked, .streamsBlockedBidi, .streamsBlockedUni, .unknown:
            break
        }
    }

    public mutating func recordData(bytes: Int) throws {
        guard isEnabled else { return }
        guard bytes >= 0 else {
            throw QUICCodecError.valueOutOfRange("negative stream payload")
        }
        let count = UInt64(bytes)
        switch maxDataState {
        case .disabled, .unlimited:
            return
        case .zero:
            throw QUICCodecError.valueOutOfRange("WebTransport session data limit exceeded")
        case .limited(let limit):
            let (newUsage, overflow) = usedData.addingReportingOverflow(count)
            guard !overflow && newUsage <= limit else {
                throw QUICCodecError.valueOutOfRange("WebTransport session data limit exceeded")
            }
            usedData = newUsage
            return
        }
    }

    public mutating func registerStream(_ form: WebTransportStreamForm) throws {
        guard isEnabled else { return }
        switch form {
        case .bidirectional:
            try ensureCanOpen(form: .bidirectional, current: openedBidiStreams, limit: maxStreamsBidiState)
            openedBidiStreams += 1
        case .unidirectional:
            try ensureCanOpen(form: .unidirectional, current: openedUniStreams, limit: maxStreamsUniState)
            openedUniStreams += 1
        }
    }

    private func ensureCanOpen(form: WebTransportStreamForm, current: Int, limit: WebTransportFlowControlLimitState) throws {
        let limit = limit.asUInt64
        guard let limit else {
            return
        }
        let next = current + 1
        let limitInt = limit > UInt64(Int.max) ? Int.max : Int(limit)
        guard next <= limitInt else {
            throw QUICCodecError.valueOutOfRange("WebTransport \(form == .bidirectional ? "bidirectional" : "unidirectional") stream limit exceeded")
        }
    }
}

private func setMonotonicLimit(
    _ current: inout WebTransportFlowControlLimitState,
    value: UInt64,
    label: String
) throws {
    let normalized = WebTransportFlowControlLimitState(value, isEnabled: true)
    if let currentValue = current.asUInt64,
       let newValue = normalized.asUInt64,
       newValue < currentValue {
        throw WebTransportDraft15Error(
            kind: .flowControl,
            message: "\(label) must not decrease"
        )
    }
    current = normalized
}

public enum WebTransportFlowControlHelpers {
    public static func blockedCapsule(for form: WebTransportStreamForm, limit: UInt64) -> WebTransportFlowCapsule {
        switch form {
        case .bidirectional:
            return .streamsBlockedBidi(limit: limit)
        case .unidirectional:
            return .streamsBlockedUni(limit: limit)
        }
    }
}
