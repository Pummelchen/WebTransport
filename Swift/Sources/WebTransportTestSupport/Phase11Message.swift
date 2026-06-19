import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore

public enum Phase11Error: Error, CustomStringConvertible {
    case frameMalformed(String)
    case envelopeMalformed(String)

    public var description: String {
        switch self {
        case .frameMalformed(let message):
            return "Frame malformed: \(message)"
        case .envelopeMalformed(let message):
            return "Envelope malformed: \(message)"
        }
    }
}

public enum Phase11MessageKind: String, Codable, Sendable {
    case hello
    case helloAck
    case control
    case controlAck
    case sessionRequest
    case sessionResponse
    case streamOpen
    case streamOpenAck
    case streamData
    case streamEcho
    case datagram
    case datagramEcho
    case streamReset
    case streamResetAck
    case resetReceived
    case scenarioDone
    case result
    case error
}

public enum Phase11Scenario: String, Codable, Sendable {
    case echoStreams
    case echoDatagrams
    case closeAndReset
    case oversizedDatagram
    case malformedFrame
    case rejectedSession
}

public enum Phase11StreamKind: String, Codable, Sendable {
    case bidirectional
    case unidirectional
}

public struct Phase11Envelope: Codable, Sendable {
    public let scenario: Phase11Scenario?
    public let kind: Phase11MessageKind
    public let requestStreamID: UInt64?
    public let streamID: UInt64?
    public let sessionID: UInt64?
    public let errorCode: UInt64?
    public let streamKind: Phase11StreamKind?
    public let status: UInt16?
    public let success: Bool?
    public let payload: Data?
    public let message: String?

    public init(
        scenario: Phase11Scenario? = nil,
        kind: Phase11MessageKind,
        requestStreamID: UInt64? = nil,
        streamID: UInt64? = nil,
        sessionID: UInt64? = nil,
        errorCode: UInt64? = nil,
        streamKind: Phase11StreamKind? = nil,
        status: UInt16? = nil,
        success: Bool? = nil,
        payload: Data? = nil,
        message: String? = nil
    ) {
        self.scenario = scenario
        self.kind = kind
        self.requestStreamID = requestStreamID
        self.streamID = streamID
        self.sessionID = sessionID
        self.errorCode = errorCode
        self.streamKind = streamKind
        self.status = status
        self.success = success
        self.payload = payload
        self.message = message
    }
}

public enum Phase11Protocol {
    public static func encode(_ envelope: Phase11Envelope) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            return try encoder.encode(envelope)
        } catch {
            throw Phase11Error.envelopeMalformed("failed to encode: \(error)")
        }
    }

    public static func decode(_ data: Data) throws -> Phase11Envelope {
        do {
            return try JSONDecoder().decode(Phase11Envelope.self, from: data)
        } catch {
            throw Phase11Error.envelopeMalformed("failed to decode: \(error)")
        }
    }
}

public enum Phase11FramePacket {
    public static func encodeHTTP3Frame(_ frame: HTTP3Frame) throws -> Data {
        do {
            return try HTTP3Frame.encodeFrames([frame])
        } catch {
            throw Phase11Error.frameMalformed("failed to encode HTTP/3 frame: \(error)")
        }
    }

    public static func decodeHTTP3Frame(_ payload: Data) throws -> HTTP3Frame {
        let frames: [HTTP3Frame]
        do {
            frames = try HTTP3Frame.decodeFrames(payload)
        } catch {
            throw Phase11Error.frameMalformed("failed to decode frames: \(error)")
        }
        guard frames.count == 1 else {
            throw Phase11Error.frameMalformed("expected one frame but received \(frames.count)")
        }
        return frames[0]
    }

    public static func encodeQUICFrame(_ frame: QUICFrame) throws -> Data {
        do {
            return try QUICFrame.encodeFrames([frame])
        } catch {
            throw Phase11Error.frameMalformed("failed to encode QUIC frame: \(error)")
        }
    }

    public static func decodeQUICFrame(_ payload: Data) throws -> QUICFrame {
        let frames: [QUICFrame]
        do {
            frames = try QUICFrame.decodeFrames(payload)
        } catch {
            throw Phase11Error.frameMalformed("failed to decode frames: \(error)")
        }
        guard frames.count == 1 else {
            throw Phase11Error.frameMalformed("expected one frame but received \(frames.count)")
        }
        return frames[0]
    }
}

public enum Phase11Payload {
    public static func utf8(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self)
    }

    public static func utf8(_ text: String) -> Data {
        Data(text.utf8)
    }
}
