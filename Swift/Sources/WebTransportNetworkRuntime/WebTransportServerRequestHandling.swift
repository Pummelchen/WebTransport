import Foundation
import CryptoKit
import Network
import Security
import Synchronization
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

/// What the server does with one CONNECT request: decode it into the policy it must satisfy,
/// resolve admission for the listener, and deliver the decision.
///
/// These three take everything they need as arguments and read no server state, so the server's own
/// file can be about the listener and the session lifecycle. The request shape and the four
/// configured values a request is checked against travel with the decoder that uses them.
enum WebTransportServerRequestHandling {
    /// The four configured values a request is checked against.
    struct RequestPolicyInputs {
        let authority: String
        let path: String
        let allowedOrigin: String?
        let protocols: [String]
    }

    /// The CONNECT request's HEADERS frame, any optimistic capsule bytes behind it, and the policy
    /// this server applies to it. Internal, not private: the server keeps one while it reads the
    /// request, and a type cannot cross a file boundary as `private`.
    struct DecodedSessionRequest {
        let frame: HTTP3Frame
        let optimisticCapsuleBytes: Data
        let policy: WebTransportServerSessionPolicy
    }

    static func decodeRequestAndPolicy(
        inputs: RequestPolicyInputs, localEndpoint: WebTransportNetworkEndpoint, requestPayload: Data
    ) throws -> DecodedSessionRequest {
        let requestFramePayload: Data
        if WebTransportStreamSignaling.hasStreamPrefix(requestPayload) {
            let prefixed = try WebTransportStreamSignaling.parsePrefix(requestPayload)
            guard prefixed.form == .bidirectional else {
                throw WebTransportDraft16Error(
                    kind: .h3ID,
                    message: "WebTransport CONNECT request stream carried a unidirectional stream marker"
                )
            }
            requestFramePayload = prefixed.remainingPayload
        } else {
            // No marker: an ordinary HTTP/3 extended CONNECT request stream.
            requestFramePayload = requestPayload
        }
        let requestPrefix = try HTTP3Frame.decodePrefix(requestFramePayload)
        guard requestPrefix.frame.type == HTTP3FrameType.headers else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }

        var allowedAuthorities = Set([inputs.authority])
        allowedAuthorities.insert("\(inputs.authority):\(localEndpoint.port)")
        allowedAuthorities.insert(localEndpoint.host)
        allowedAuthorities.insert("\(localEndpoint.host):\(localEndpoint.port)")
        let policy = try WebTransportServerSessionPolicy(
            allowedAuthorities: allowedAuthorities,
            allowedPaths: [inputs.path],
            allowedOrigins: inputs.allowedOrigin.map { [$0] },
            supportedProtocols: inputs.protocols,
            requireProtocolSelection: !inputs.protocols.isEmpty
        )
        return DecodedSessionRequest(
            frame: requestPrefix.frame,
            optimisticCapsuleBytes: Data(requestFramePayload.dropFirst(requestPrefix.bytesConsumed)),
            policy: policy
        )
    }
    static func deliverSessionDecision(
        _ decision: WebTransportServerSessionDecision,
        on requestStream: QUIC.Stream<QUICStream>,
        remainingTimeout: @escaping @Sendable () -> Int32,
        totalTimeoutMilliseconds: Int32
    ) async throws {
        InteroperableQUICDebug.log(
            "server CONNECT decision: session=\(decision.session.id) "
                + "protocol=\(decision.session.selectedProtocol ?? "none") "
                + "rejection=\(decision.rejectionError.map { "\($0)" } ?? "none")"
        )
        let responsePayload = try decision.responseFrame.encode()
        let remaining = remainingTimeout()
        guard remaining > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        try await InteroperableQUICHelpers.withTimeout(remaining) {
            try await requestStream.send(responsePayload, endOfStream: false)
        }
    }
    static func resolvedAdmission(
        _ admission: WebTransportAdmissionPolicy,
        maxConcurrentConnections: Int?
    ) throws -> WebTransportAdmissionPolicy {
        var resolved = try admission.validated()
        if let maxConcurrentConnections {
            guard maxConcurrentConnections > 0 else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    "maxConcurrentConnections must be positive"
                )
            }
            resolved.maxConcurrentConnections = maxConcurrentConnections
        }
        return resolved
    }
}
