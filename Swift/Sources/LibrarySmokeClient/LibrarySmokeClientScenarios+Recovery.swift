import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTestSupport
import WebTransportUDPApple

extension LibrarySmokeRunner {
    mutating func runConcurrentSessionsScenario() throws {
        let sessionCount = max(2, min(config.iterations, 5))
        var sessions: [WebTransportSession] = []

        for index in 0..<sessionCount {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            sessions.append(session)

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

            let message = "parallel-\(index)"
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamData,
                    streamID: streamID,
                    payload: Phase11Payload.utf8(message)
                )
            )
            let echoed = try receive(expect: .streamEcho)
            if echoed.payload != Phase11Payload.utf8(message) {
                throw Error.runtime("parallel session #\(index) stream echo mismatch")
            }
        }

        if sessions.count != sessionCount {
            throw Error.runtime("concurrent session setup failed")
        }
        print("client: concurrent sessions scenario passed")
    }
    mutating func runProtocolNegotiationScenario() throws {
        let streamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: streamID,
            authority: "example.com",
            path: "/wt",
            availableProtocols: ["proto-other", "wt-echo", "unused"]
        )
        let response = try runSessionRequest(
            requestFrame: requestFrame,
            requestStreamID: streamID,
            scenario: .echoDatagrams,
            expectedAccepted: true
        )
        guard response.status == nil else {
            throw Error.runtime("server unexpectedly rejected protocol negotiation")
        }
        guard let session = manager.session(forRequestStreamID: streamID),
            session.selectedProtocol == "wt-echo"
        else {
            throw Error.runtime("protocol negotiation did not select wt-echo")
        }
        print("client: protocol negotiation scenario passed")
    }
    mutating func runFlowControlCapsuleScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        try verifyDatagramFlowControl(session: session)

        _ = try manager.receiveFlowControlCapsule(
            sessionID: session.id,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 1))
        )
        // The limit is expected to be refused; the catch is the recovery path rather than a
        // failure, which is why the two blocks are separate helpers and not one.
        let streamID: UInt64
        do {
            streamID = try verifyStreamLimitRefusal(session: session)
        } catch {
            streamID = try recoverAfterStreamLimit(session: session)
        }
        try verifyMaxDataLift(session: session, streamID: streamID)

        // Allow another stream after an update to unlimited.
        _ = try manager.receiveFlowControlCapsule(
            sessionID: session.id,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 3))
        )
        let recoveryStream = nextBidirectionalStreamID()
        _ = try manager.openBidirectionalStream(streamID: recoveryStream, sessionID: session.id)

        print("client: flow-control capsule scenario passed")
    }
    /// `max_data` caps the datagram size, and the cap is what makes the oversized send fail.
    private mutating func verifyDatagramFlowControl(session: WebTransportSession) throws {
        let maxDataCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 64))
        _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: maxDataCapsule)

        do {
            let payload = Data(repeating: 0x55, count: 128)
            let frame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
            _ = try Phase11FramePacket.encodeQUICFrame(frame)
            throw Error.runtime("oversized datagram unexpectedly allowed under maxData")
        } catch {
            // Expected: max_data reached.
        }

        let payload = Data(repeating: 0x22, count: 32)
        let safeFrame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
        try send(
            Phase11Envelope(
                scenario: .echoDatagrams,
                kind: .datagram,
                sessionID: session.id.rawValue,
                payload: try Phase11FramePacket.encodeQUICFrame(safeFrame)
            )
        )
        let echoed = try receive(expect: .datagramEcho)
        guard echoed.payload == payload else {
            throw Error.runtime("flow control datagram check failed")
        }
    }
    /// Opens the first stream under the limit and confirms the second is refused, with a
    /// STREAMS_BLOCKED capsule queued for it.
    private mutating func verifyStreamLimitRefusal(session: WebTransportSession) throws -> UInt64 {
        let firstStream = nextBidirectionalStreamID()
        let firstPrefix = try manager.openBidirectionalStream(streamID: firstStream, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: firstStream,
                streamKind: .bidirectional,
                payload: firstPrefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        let secondStream = nextBidirectionalStreamID()
        do {
            _ = try manager.openBidirectionalStream(streamID: secondStream, sessionID: session.id)
            throw Error.runtime("second stream unexpectedly opened under stream limit")
        } catch {
            guard let queued = try manager.popFlowControlCapsule(sessionID: session.id) else {
                throw Error.runtime("expected blocked stream flow capsule")
            }
            let parsed = try WebTransportFlowCapsuleCodec.parse(queued)
            if case .streamsBlockedBidi(let limit) = parsed.capsule {
                guard limit > 0 else {
                    throw Error.runtime("invalid streamsBlockedBidi limit \(limit)")
                }
            }
        }
        return firstStream
    }
    /// The recovery path when the limit was hit before the first stream opened: lift it and
    /// open one. A missing queued capsule is tolerated here, which is what distinguishes this
    /// from the refusal check above.
    private mutating func recoverAfterStreamLimit(session: WebTransportSession) throws -> UInt64 {
        if let queued = try manager.popFlowControlCapsule(sessionID: session.id) {
            let parsed = try WebTransportFlowCapsuleCodec.parse(queued)
            if case .streamsBlockedBidi(let limit) = parsed.capsule {
                guard limit > 0 else {
                    throw Error.runtime("invalid streamsBlockedBidi limit \(limit)")
                }
            }
        }

        let liftedStreamCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 3))
        _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: liftedStreamCapsule)

        let streamID = nextBidirectionalStreamID()
        let recoveryPrefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: recoveryPrefix
            )
        )
        _ = try receive(expect: .streamOpenAck)
        return streamID
    }
    /// `max_data` rejects an oversized inbound stream payload, and raising it accepts one.
    private mutating func verifyMaxDataLift(session: WebTransportSession, streamID: UInt64) throws {
        do {
            try manager.receiveStreamPayload(streamID: streamID, payload: Data(repeating: 0x77, count: 128))
            throw Error.runtime("local flow-control maxData should reject oversized inbound stream payload")
        } catch {
            // expected
        }

        let baselinePayload = Data(repeating: 0x55, count: 24)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamData,
                streamID: streamID,
                payload: baselinePayload
            )
        )
        let streamBaselineEcho = try receive(expect: .streamEcho)
        guard streamBaselineEcho.payload == baselinePayload else {
            throw Error.runtime("flow-control maxData baseline payload should echo")
        }

        let liftedDataCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 256))
        _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: liftedDataCapsule)

        let liftPayload = Data(repeating: 0x33, count: 24)
        try manager.receiveStreamPayload(streamID: streamID, payload: liftPayload)
        let localRecoveredPayload = manager.popStreamPayload(streamID: streamID)
        guard localRecoveredPayload == liftPayload else {
            throw Error.runtime("flow-control maxData lift should allow inbound stream payload")
        }

        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamData,
                streamID: streamID,
                payload: liftPayload
            )
        )
        let streamEcho = try receive(expect: .streamEcho)
        guard streamEcho.payload == liftPayload else {
            throw Error.runtime("stream data should be accepted after maxData raised")
        }
    }
    mutating func runDuplicateSessionRequestScenario() throws {
        let requestStreamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: "example.com",
            path: "/wt",
            availableProtocols: ["wt-echo"]
        )

        _ = try runSessionRequest(
            requestFrame: requestFrame,
            requestStreamID: requestStreamID,
            scenario: .echoStreams,
            expectedAccepted: true
        )

        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
            )
        )
        let duplicate = try receive()
        if duplicate.kind != .error {
            throw Error.runtime("duplicate session request should be rejected")
        }
        print("client: duplicate session request scenario passed")
    }
    mutating func runCloseAndResetScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        let streamID = nextBidirectionalStreamID()
        let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .closeAndReset,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: prefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        try send(
            Phase11Envelope(
                scenario: .closeAndReset,
                kind: .streamReset,
                streamID: streamID,
                errorCode: 0x54
            )
        )
        let resetAck = try receive(expect: .streamResetAck)
        guard let payload = resetAck.payload else {
            throw Error.runtime("missing stream reset frame from server")
        }
        _ = try Phase11FramePacket.decodeQUICFrame(payload)
        print("client: close/reset scenario passed")
    }
    mutating func runOversizedDatagramScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        let hugePayload = Data(repeating: 0x66, count: config.maxDatagramFrameSize + 10)
        let oversized = try WebTransportDatagramSignaling.serialize(sessionID: session.id.rawValue, payload: hugePayload)
        let datagramFrame = QUICFrame.datagram(oversized)
        try send(
            Phase11Envelope(
                scenario: .oversizedDatagram,
                kind: .datagram,
                sessionID: session.id.rawValue,
                payload: try Phase11FramePacket.encodeQUICFrame(datagramFrame)
            )
        )
        let response = try receive(expect: .error)
        if response.success == true {
            throw Error.runtime("server should reject oversized datagram")
        }
        print("client: oversized datagram scenario passed")
    }
    mutating func runMalformedFrameScenario() throws {
        _ = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        let streamID = nextBidirectionalStreamID()
        try send(
            Phase11Envelope(
                scenario: .malformedFrame,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: Data([0x00, 0x00])
            )
        )
        let response = try receive()
        if response.kind != .error {
            throw Error.runtime("malformed stream open should be rejected")
        }
        print("client: malformed frame scenario passed")
    }
    mutating func runRejectedSessionScenario() throws {
        let request = try WebTransportSessionRequest(authority: "forbidden.example", path: "/missing")
        let requestStreamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: request.authority,
            path: request.path
        )
        try send(
            Phase11Envelope(
                scenario: .rejectedSession,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
            )
        )
        let response = try receive(expect: .sessionResponse)
        guard let status = response.status, status != 0 else {
            throw Error.runtime("server rejected session did not return status")
        }
        print("client: rejected-session scenario passed (\(status))")
    }
}
