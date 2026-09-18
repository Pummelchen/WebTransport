import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTestSupport
import WebTransportUDPApple

struct LibrarySmokeRunner {
    enum Error: Swift.Error, CustomStringConvertible {
        case syntax(String)
        case runtime(String)
        case transport(String)

        var description: String {
            switch self {
            case .syntax(let message):
                return "syntax error: \(message)"
            case .runtime(let message):
                return "runtime error: \(message)"
            case .transport(let message):
                return "transport error: \(message)"
            }
        }
    }

    struct Config {
        var host = "127.0.0.1"
        var port: UInt16 = 45500
        var iterations = 4
        var maxDatagramFrameSize = 1_200
        var maxDatagramReceiveBufferBytes = 64 * 1024
        var runSuite = true
    }

    let config: Config
    let client: QUICUDPPort
    let serverEndpoint: QUICUDPEndpoint
    var manager: WebTransportSessionManager
    var nextClientRequestStreamIndex: UInt64 = 0
    var nextClientBidiStreamIndex: UInt64 = 1
    var nextClientUniStreamIndex: UInt64 = 0
    var nextServerBidiStreamIndex: UInt64 = 0
    var nextServerUniStreamIndex: UInt64 = 1

    init(config: Config) throws {
        self.config = config
        self.client = try QUICUDPPort()
        self.serverEndpoint = QUICUDPEndpoint(host: config.host, port: config.port)
        self.manager = WebTransportSessionManager(
            http3: HTTP3ConnectionState(role: .client),
            maxDatagramFrameSize: config.maxDatagramFrameSize,
            maxDatagramReceiveBufferBytes: config.maxDatagramReceiveBufferBytes
        )
        print("LibrarySmokeClient local port: \(client.localEndpoint.port)")
        print("LibrarySmokeClient running in \(config.runSuite ? "suite" : "quick") mode")
    }

    mutating func run() throws {
        let scenarioID: Phase11Scenario = .echoStreams

        try send(Phase11Envelope(scenario: scenarioID, kind: .hello))
        _ = try receive(expect: .helloAck)

        let localControl = try manager.http3.localControlStreamBytes()
        try send(
            Phase11Envelope(
                scenario: scenarioID,
                kind: .control,
                payload: localControl
            )
        )
        let controlAck = try receive(expect: .controlAck)
        guard let peerControl = controlAck.payload else {
            throw Error.transport("missing control response payload")
        }
        _ = try manager.receivePeerControlStream(peerControl)

        if config.runSuite {
            try runSuite()
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .result,
                    success: true,
                    message: "suite complete"
                )
            )
        } else {
            try runQuick()
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .result,
                    success: true,
                    message: "checks complete"
                )
            )
        }

        _ = try receive(expect: .result)
    }

    mutating func runQuick() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        let streamID = nextBidirectionalStreamID()

        let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: prefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        let outbound = Phase11Payload.utf8("stream-hello")
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamData,
                streamID: streamID,
                payload: outbound
            )
        )
        let echoed = try receive(expect: .streamEcho)
        guard echoed.payload == outbound else {
            throw Error.runtime("stream echo payload mismatch")
        }

        try runEchoDatagrams(session: session, scenario: .echoDatagrams)
        print("client: quick smoke checks passed")
    }
}

extension LibrarySmokeRunner {
    mutating func runSessionRequest(
        requestFrame: HTTP3Frame,
        requestStreamID: UInt64,
        scenario: Phase11Scenario,
        expectedAccepted: Bool
    ) throws -> Phase11Envelope {
        try send(
            Phase11Envelope(
                scenario: scenario,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
            )
        )

        let response = try receive(expect: .sessionResponse)
        guard let payload = response.payload else {
            throw Error.runtime("missing session response payload")
        }
        let responseFrame = try Phase11FramePacket.decodeHTTP3Frame(payload)
        _ = try manager.receiveServerSessionResponse(streamID: requestStreamID, frame: responseFrame)
        print("client: manager has session? \(manager.session(forRequestStreamID: requestStreamID) != nil)")

        if expectedAccepted && response.status != nil {
            throw Error.runtime("session rejected unexpectedly with status \(String(describing: response.status))")
        }
        if !expectedAccepted && response.status == nil {
            throw Error.runtime("session accepted unexpectedly")
        }
        return response
    }

    mutating func send(_ envelope: Phase11Envelope) throws {
        let encoded = try Phase11Protocol.encode(envelope)
        try client.send(encoded, to: serverEndpoint)
    }

    mutating func receive(expect expected: Phase11MessageKind? = nil) throws -> Phase11Envelope {
        let (bytes, _) = try client.receive(timeoutMilliseconds: 10_000)
        let envelope = try Phase11Protocol.decode(bytes)
        if let expected,
            envelope.kind != expected
        {
            throw Error.transport("expected \(expected) got \(envelope.kind)")
        }
        return envelope
    }

    mutating func nextRequestStreamID() -> UInt64 {
        let streamID = nextClientRequestStreamIndex
        nextClientRequestStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .client)
    }

    mutating func nextServerBidiStreamID() -> UInt64 {
        let streamID = nextServerBidiStreamIndex
        nextServerBidiStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .server)
    }

    mutating func nextServerUniStreamID() -> UInt64 {
        let streamID = nextServerUniStreamIndex
        nextServerUniStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .unidirectional, initiator: .server)
    }

    mutating func nextBidirectionalStreamID() -> UInt64 {
        let streamID = nextClientBidiStreamIndex
        nextClientBidiStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .client)
    }

    mutating func nextUnidirectionalStreamID() -> UInt64 {
        let streamID = nextClientUniStreamIndex
        nextClientUniStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .unidirectional, initiator: .client)
    }
}

extension LibrarySmokeRunner {
    mutating func runSuite() throws {
        let suiteStart = Date()
        print("client: starting smoke suite")

        var start = Date()
        do {
            print("client: running echo streams (multi-stream)")
            try runEchoStreamsScenario()
            print("client: ✓ echo streams (multi-stream) in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step echo streams (multi-stream) failed: \(error)")
        }

        start = Date()
        do {
            print("client: running control stream reuse")
            try runControlStreamReuseScenario()
            print("client: ✓ control stream reuse in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step control stream reuse failed: \(error)")
        }

        start = Date()
        do {
            print("client: running datagram burst")
            try runEchoDatagramBurst()
            print("client: ✓ datagram burst in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step datagram burst failed: \(error)")
        }

        start = Date()
        do {
            print("client: running datagram ordering and buffer boundary")
            try runDatagramOrderingScenario()
            print("client: ✓ datagram ordering in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step datagram ordering failed: \(error)")
        }

        start = Date()
        do {
            print("client: running interleaved stream flow")
            try runInterleavedStreamScenario()
            print("client: ✓ interleaved stream flow in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step interleaved stream flow failed: \(error)")
        }

        start = Date()
        do {
            print("client: running concurrent sessions")
            try runConcurrentSessionsScenario()
            print("client: ✓ concurrent sessions in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step concurrent sessions failed: \(error)")
        }

        start = Date()
        do {
            print("client: running protocol negotiation")
            try runProtocolNegotiationScenario()
            print("client: ✓ protocol negotiation in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step protocol negotiation failed: \(error)")
        }

        start = Date()
        do {
            print("client: running flow-control capsules")
            try runFlowControlCapsuleScenario()
            print("client: ✓ flow-control capsules in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step flow-control capsules failed: \(error)")
        }

        start = Date()
        do {
            print("client: running stream identity + duplicate open")
            try runStreamIdentityAndDuplicateOpenScenario()
            print("client: ✓ stream identity + duplicate open in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step stream identity + duplicate open failed: \(error)")
        }

        start = Date()
        do {
            print("client: running malformed stream open")
            try runMalformedStreamScenario()
            print("client: ✓ malformed stream open in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step malformed stream open failed: \(error)")
        }

        start = Date()
        do {
            print("client: running datagram/session integrity")
            try runDatagramIntegrityScenario()
            print("client: ✓ datagram/session integrity in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step datagram/session integrity failed: \(error)")
        }

        start = Date()
        do {
            print("client: running malformed datagram frame")
            try runMalformedDatagramScenario()
            print("client: ✓ malformed datagram frame in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step malformed datagram frame failed: \(error)")
        }

        start = Date()
        do {
            print("client: running duplicate session request")
            try runDuplicateSessionRequestScenario()
            print("client: ✓ duplicate session request in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step duplicate session request failed: \(error)")
        }

        start = Date()
        do {
            print("client: running malformed session request")
            try runMalformedSessionRequestScenario()
            print("client: ✓ malformed session request in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step malformed session request failed: \(error)")
        }

        start = Date()
        do {
            print("client: running close/reset path")
            try runCloseAndResetScenario()
            print("client: ✓ close/reset path in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step close/reset path failed: \(error)")
        }

        start = Date()
        do {
            print("client: running session rejection")
            try runRejectedSessionScenario()
            print("client: ✓ session rejection in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step session rejection failed: \(error)")
        }

        start = Date()
        do {
            print("client: running oversized datagram rejection")
            try runOversizedDatagramScenario()
            print("client: ✓ oversized datagram rejection in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step oversized datagram rejection failed: \(error)")
        }

        start = Date()
        do {
            print("client: running malformed stream open")
            try runMalformedFrameScenario()
            print("client: ✓ malformed frame path in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step malformed frame failed: \(error)")
        }

        let elapsed = Date().timeIntervalSince(suiteStart)
        print("client: full suite checks passed in \(formatDuration(elapsed))s")
    }

    mutating func establishAcceptedSession(
        authority: String,
        path: String,
        includeOrigin: Bool = false,
        availableProtocols: [String] = ["wt-echo"],
        requestStreamID: UInt64
    ) throws -> WebTransportSession {
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: authority,
            path: path,
            includeOrigin: includeOrigin,
            availableProtocols: availableProtocols
        )
        _ = try runSessionRequest(
            requestFrame: requestFrame,
            requestStreamID: requestStreamID,
            scenario: .echoStreams,
            expectedAccepted: true
        )

        guard let session = manager.session(forRequestStreamID: requestStreamID) else {
            throw Error.runtime("client session missing after request")
        }
        print("client: established session id \(session.id.rawValue) on request stream \(requestStreamID)")
        return session
    }

    mutating func establishRejectedSession() throws {
        let request = try WebTransportSessionRequest(authority: "forbidden.example", path: "/missing")
        let requestStreamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: request.authority,
            path: request.path
        )
        let encoded = try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
        try send(
            Phase11Envelope(
                scenario: .rejectedSession,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: encoded
            )
        )
        let response = try receive(expect: .sessionResponse)
        _ = try Phase11FramePacket.decodeHTTP3Frame(response.payload ?? Data())
        _ = response.status
    }

    mutating func makeSessionRequestFrame(
        requestStreamID: UInt64,
        authority: String,
        path: String,
        includeOrigin: Bool = false,
        availableProtocols: [String] = ["wt-echo"]
    ) throws -> HTTP3Frame {
        let request = try WebTransportSessionRequest(
            authority: authority,
            path: path,
            origin: includeOrigin ? "https://\(authority)" : nil,
            availableProtocols: availableProtocols
        )
        return try manager.makeClientSessionRequest(streamID: requestStreamID, request: request)
    }
}
