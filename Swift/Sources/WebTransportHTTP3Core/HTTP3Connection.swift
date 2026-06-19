import Foundation
import WebTransportQUICCore

public enum HTTP3ConnectionRole: Equatable, Sendable {
    case client
    case server
}

public enum HTTP3ApplicationErrorCode: UInt64, Equatable, Sendable {
    case noError = 0x100
    case generalProtocolError = 0x101
    case internalError = 0x102
    case streamCreationError = 0x103
    case closedCriticalStream = 0x104
    case frameUnexpected = 0x105
    case frameError = 0x106
    case excessLoad = 0x107
    case idError = 0x108
    case settingsError = 0x109
    case missingSettings = 0x10a
    case requestRejected = 0x10b
    case requestCancelled = 0x10c
    case requestIncomplete = 0x10d
    case messageError = 0x10e
    case connectError = 0x10f
    case versionFallback = 0x110
}

public enum HTTP3DataFramePolicy: Equatable, Sendable {
    case reject
    case buffer
}

public enum HTTP3RequestStreamState: Equatable, Sendable {
    case idle
    case open
    case halfClosedRemote
    case closed
}

public struct HTTP3RequestStream: Equatable, Sendable {
    public let streamID: UInt64
    public let role: HTTP3ConnectionRole
    public private(set) var state: HTTP3RequestStreamState
    public private(set) var requestHeaders: [HTTPFieldLine]?
    public private(set) var responseHeaders: [HTTPFieldLine]?
    public private(set) var dataChunks: [Data]

    public init(streamID: UInt64, role: HTTP3ConnectionRole) {
        self.streamID = streamID
        self.role = role
        self.state = .idle
        self.requestHeaders = nil
        self.responseHeaders = nil
        self.dataChunks = []
    }

    public mutating func makeRequestHeadersFrame(_ fields: [HTTPFieldLine]) throws -> HTTP3Frame {
        guard role == .client else {
            throw QUICCodecError.malformed("only clients send HTTP/3 request HEADERS")
        }
        guard state == .idle else {
            throw QUICCodecError.malformed("request HEADERS already sent")
        }
        try WebTransportHTTP3Headers.validateConnectRequest(fields)
        requestHeaders = fields
        state = .open
        return try QPACK.headersFrame(fields: fields)
    }

    public mutating func makeResponseHeadersFrame(_ fields: [HTTPFieldLine]) throws -> HTTP3Frame {
        guard role == .server else {
            throw QUICCodecError.malformed("only servers send HTTP/3 response HEADERS")
        }
        guard state == .open || state == .halfClosedRemote else {
            throw QUICCodecError.malformed("response HEADERS require an open request stream")
        }
        try WebTransportHTTP3Headers.validateSuccessfulResponse(fields)
        responseHeaders = fields
        state = .open
        return try QPACK.headersFrame(fields: fields)
    }

    public mutating func receive(
        frame: HTTP3Frame,
        dataPolicy: HTTP3DataFramePolicy = .reject,
        qpackLimits: QPACKDecoderLimits = .default
    ) throws {
        switch frame.type {
        case HTTP3FrameType.headers:
            let headers = try QPACK.decodeHeadersFrame(frame, limits: qpackLimits)
            try receiveHeaders(headers)
        case HTTP3FrameType.data:
            try receiveData(frame.payload, policy: dataPolicy)
        case HTTP3FrameType.goaway, HTTP3FrameType.settings:
            throw QUICCodecError.malformed("connection-level HTTP/3 frame received on request stream")
        default:
            return
        }
    }

    public mutating func receiveHeaders(_ fields: [HTTPFieldLine]) throws {
        switch role {
        case .client:
            guard state == .open || state == .halfClosedRemote else {
                throw QUICCodecError.malformed("client received response HEADERS in invalid request state")
            }
            try WebTransportHTTP3Headers.validateSuccessfulResponse(fields)
            responseHeaders = fields
            state = .open
        case .server:
            guard state == .idle else {
                throw QUICCodecError.malformed("server received duplicate request HEADERS")
            }
            try WebTransportHTTP3Headers.validateConnectRequest(fields)
            requestHeaders = fields
            state = .open
        }
    }

    public mutating func receiveData(_ data: Data, policy: HTTP3DataFramePolicy) throws {
        guard state == .open || state == .halfClosedRemote else {
            throw QUICCodecError.malformed("DATA received in invalid request state")
        }
        switch policy {
        case .reject:
            throw QUICCodecError.malformed("DATA frames are not accepted on WebTransport CONNECT request streams")
        case .buffer:
            dataChunks.append(data)
        }
    }

    public mutating func finishRemote() throws {
        switch state {
        case .idle:
            throw QUICCodecError.malformed("request stream ended before HEADERS")
        case .open:
            state = .halfClosedRemote
        case .halfClosedRemote, .closed:
            return
        }
    }
}

public struct HTTP3ConnectionState: Equatable, Sendable {
    public let role: HTTP3ConnectionRole
    public var localSettings: HTTP3Settings
    public private(set) var remoteSettings: HTTP3Settings?
    public private(set) var receivedPeerControlStream: Bool
    public private(set) var sentGoawayID: UInt64?
    public private(set) var receivedGoawayID: UInt64?
    public private(set) var requestStreams: [UInt64: HTTP3RequestStream]

    public init(role: HTTP3ConnectionRole, localSettings: HTTP3Settings = HTTP3Settings.webTransportDraft15Defaults) {
        self.role = role
        self.localSettings = localSettings
        self.remoteSettings = nil
        self.receivedPeerControlStream = false
        self.sentGoawayID = nil
        self.receivedGoawayID = nil
        self.requestStreams = [:]
    }

    public func localControlStreamBytes() throws -> Data {
        try HTTP3StreamTypeParser.encodePrefix(
            type: HTTP3StreamType.control,
            payload: localSettings.frame().encode()
        )
    }

    public mutating func receivePeerControlStream(_ bytes: Data) throws -> [HTTP3Frame] {
        guard !receivedPeerControlStream else {
            throw QUICCodecError.malformed("duplicate HTTP/3 control stream")
        }
        let prefix = try HTTP3StreamTypeParser.parsePrefix(bytes)
        guard prefix.type == HTTP3StreamType.control else {
            throw QUICCodecError.malformed("expected HTTP/3 control stream")
        }
        let frames = try HTTP3Frame.decodeFrames(prefix.remainingBytes)
        guard let firstFrame = frames.first, firstFrame.type == HTTP3FrameType.settings else {
            throw QUICCodecError.malformed("HTTP/3 control stream must start with SETTINGS")
        }

        let decodedSettings = try HTTP3Settings.decodeFrame(firstFrame)
        try decodedSettings.validateWebTransportDraft15Requirements()

        var receivedGoawayID = self.receivedGoawayID
        for frame in frames.dropFirst() {
            switch frame.type {
            case HTTP3FrameType.settings:
                throw QUICCodecError.malformed("duplicate HTTP/3 SETTINGS frame")
            case HTTP3FrameType.goaway:
                receivedGoawayID = try frame.singleVarIntPayload()
            case HTTP3FrameType.data, HTTP3FrameType.headers:
                throw QUICCodecError.malformed("request-only HTTP/3 frame received on control stream")
            default:
                break
            }
        }

        remoteSettings = decodedSettings
        self.receivedGoawayID = receivedGoawayID
        receivedPeerControlStream = true
        return frames
    }

    public mutating func receiveControlFrame(_ frame: HTTP3Frame) throws {
        switch frame.type {
        case HTTP3FrameType.settings:
            throw QUICCodecError.malformed("duplicate HTTP/3 SETTINGS frame")
        case HTTP3FrameType.goaway:
            receivedGoawayID = try frame.singleVarIntPayload()
        case HTTP3FrameType.data, HTTP3FrameType.headers:
            throw QUICCodecError.malformed("request-only HTTP/3 frame received on control stream")
        default:
            if HTTP3FrameType.isReserved(frame.type) {
                return
            }
        }
    }

    public mutating func makeGoawayFrame(streamID: UInt64) throws -> HTTP3Frame {
        sentGoawayID = streamID
        return try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: streamID)
    }

    public mutating func openRequestStream(streamID: UInt64) throws -> HTTP3RequestStream {
        guard role == .client else {
            throw QUICCodecError.malformed("only clients open request streams")
        }
        try validateClientInitiatedBidirectionalStreamID(streamID)
        guard requestStreams[streamID] == nil else {
            throw QUICCodecError.malformed("HTTP/3 request stream already exists")
        }
        let stream = HTTP3RequestStream(streamID: streamID, role: role)
        requestStreams[streamID] = stream
        return stream
    }

    public mutating func acceptRequestStream(streamID: UInt64) throws -> HTTP3RequestStream {
        guard role == .server else {
            throw QUICCodecError.malformed("only servers accept request streams")
        }
        try validateClientInitiatedBidirectionalStreamID(streamID)
        guard requestStreams[streamID] == nil else {
            throw QUICCodecError.malformed("HTTP/3 request stream already exists")
        }
        let stream = HTTP3RequestStream(streamID: streamID, role: role)
        requestStreams[streamID] = stream
        return stream
    }

    public mutating func storeRequestStream(_ stream: HTTP3RequestStream) {
        requestStreams[stream.streamID] = stream
    }

    public func closeFrame(
        error: HTTP3ApplicationErrorCode,
        reason: String,
        frameType: UInt64? = nil
    ) -> QUICFrame {
        .connectionClose(errorCode: error.rawValue, frameType: frameType, reason: Data(reason.utf8))
    }

    private func validateClientInitiatedBidirectionalStreamID(_ streamID: UInt64) throws {
        guard QUICStreamID.direction(of: streamID) == .bidirectional,
              QUICStreamID.initiator(of: streamID) == .client else {
            throw QUICCodecError.malformed("HTTP/3 request streams must be client-initiated bidirectional streams")
        }
    }
}

extension HTTP3Settings {
    public func validateWebTransportDraft15Requirements() throws {
        let constants = WebTransportHTTP3DraftConstants.current
        guard self[constants.settingsEnableConnectProtocol] == 1 else {
            throw QUICCodecError.malformed("WebTransport over HTTP/3 requires SETTINGS_ENABLE_CONNECT_PROTOCOL = 1")
        }
        guard self[constants.settingsH3Datagram] == 1 else {
            throw QUICCodecError.malformed("WebTransport over HTTP/3 requires SETTINGS_H3_DATAGRAM = 1")
        }
        guard self[constants.settingsWTEnabled] == 1 else {
            throw QUICCodecError.malformed("WebTransport over HTTP/3 requires SETTINGS_WT_ENABLE_WEBTRANSPORT = 1")
        }
    }
}
