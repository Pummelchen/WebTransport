/// How much of a requirement family the shipped product actually covers.
///
/// The type has to be able to describe less than a full pass, or the matrix is a
/// tautology: with `pass` as the only case, `allPass` could never be false and
/// nothing could record a gap. `partial` is the honest state for a family whose
/// protocol implementation exists and is conformance-tested but is not wired
/// into every shipped entry point (see the flow-control row).
public enum WebTransportDraft16ComplianceStatus: String, Equatable, Sendable {
    /// The family is implemented, conformance-tested, and reachable from the
    /// shipped products.
    case pass = "PASS"
    /// Implemented and tested in the protocol core, but not wired end to end in
    /// every shipped entry point.
    case partial = "PARTIAL"
    /// Not implemented.
    case notImplemented = "NOT_IMPLEMENTED"
    /// Not yet established either way.
    case unknown = "UNKNOWN"
}

public struct WebTransportDraft16ComplianceItem: Equatable, Sendable {
    public var requirementFamily: String
    public var status: WebTransportDraft16ComplianceStatus
    public var documentedBehavior: String
    public var evidence: [String]

    public init(
        requirementFamily: String,
        status: WebTransportDraft16ComplianceStatus,
        documentedBehavior: String,
        evidence: [String]
    ) {
        self.requirementFamily = requirementFamily
        self.status = status
        self.documentedBehavior = documentedBehavior
        self.evidence = evidence
    }
}

public enum WebTransportDraft16ComplianceMatrix {
    public static let definitionOfDone: [WebTransportDraft16ComplianceItem] = [
        WebTransportDraft16ComplianceItem(
            requirementFamily: "Session establishment and application protocol negotiation",
            status: .pass,
            documentedBehavior:
                "Extended CONNECT setup, protocol negotiation, 405 resource rejection, excess-session rejection, optimistic capsules, and session ID "
                + "mapping are implemented and documented.",
            evidence: ["WebTransportSessionTests", "WebTransportDraft16Tests", "WebTransportPublicAPITests"]
        ),
        WebTransportDraft16ComplianceItem(
            requirementFamily: "Streams and datagrams, including buffered ingress and rejection behavior",
            status: .pass,
            documentedBehavior:
                "WebTransport stream/datagram prefixes, ownership, routing, buffering, rejection cleanup, and bounded ingress are implemented and "
                + "documented. The shipped runtime opens and accepts bidirectional streams and accepts a peer-initiated unidirectional stream as a "
                + "receive-only stream; the runtime serves exactly one session per connection, so a unidirectional stream whose prefix names another "
                + "session is refused with WT_SESSION_GONE before it is registered or buffered. Opening a locally initiated unidirectional stream is "
                + "not exposed by the shipped WebTransport session API.",
            evidence: [
                "WebTransportStreamTests",
                "WebTransportDatagramTests",
                "WebTransportPhase13Tests",
                "WebTransportUnidirectionalStreamAcceptTests",
                "WebTransportLibrarySmokeMatrix",
                "run-third-party-interop.sh datagram exchange proof",
            ]
        ),
        WebTransportDraft16ComplianceItem(
            requirementFamily: "Session close/drain behavior",
            status: .pass,
            documentedBehavior:
                "WT_DRAIN_SESSION, 1024-byte UTF-8 WT_CLOSE_SESSION validation, H3_MESSAGE_ERROR reset behavior, CONNECT FIN close equivalence, "
                + "stream cleanup, and post-close gating are implemented and documented.",
            evidence: ["WebTransportDraft16Tests", "WebTransportPhase13Tests", "WebTransportLibrarySmokeMatrix"]
        ),
        WebTransportDraft16ComplianceItem(
            requirementFamily: "Flow-control and error codes",
            status: .partial,
            documentedBehavior:
                "Both-peer flow-control negotiation, directional stream-byte accounting, missing-setting zero defaults, strictly increasing WT_MAX_* "
                + "capsules, the 2^60 stream ceiling, blocked capsules, and prohibited HTTP/2 capsule handling are implemented in "
                + "WebTransportHTTP3Core and exercised by the conformance suite. The shipped Network.framework runtime does not advertise "
                + "SETTINGS_WT_INITIAL_MAX_* and so never negotiates WebTransport flow control; it admits one session per connection, and the "
                + "multi-session path that flow control gates is reachable only through WebTransportSessionManager, not through "
                + "WebTransportNetworkRuntime.",
            evidence: ["WebTransportDraft16Tests", "WebTransportFlowControlTests", "WebTransportPhase13Tests"]
        ),
        WebTransportDraft16ComplianceItem(
            requirementFamily: "H3 control and request stream constraints",
            status: .pass,
            documentedBehavior:
                "HTTP/3 SETTINGS, GOAWAY, request stream lifecycle, DATA policy, malformed ordering, and control-stream constraints are implemented "
                + "and documented.",
            evidence: ["HTTP3ConnectionTests", "HTTP3CoreTests", "WebTransportPhase13Tests"]
        ),
        WebTransportDraft16ComplianceItem(
            requirementFamily: "Security and identity handling without prompts",
            status: .partial,
            documentedBehavior:
                "ALPN/settings/session-policy negatives, prompt-free identity inputs, deterministic trust failures, and the EXPORTER-WebTransport "
                + "TLS binding are implemented and documented. Pinned-certificate trust (TLSPinnedCertificateTrustPolicy) and the CertificateVerify "
                + "verifier (TLSCertificateVerifier) are implemented and conformance-tested in WebTransportTLSCore, but they are not wired into the "
                + "shipped client path: WebTransportQUICPeerTrustPolicy offers only systemTrust and localDevelopmentSelfSigned, and "
                + "WebTransportNetworkRuntime delegates certificate and signature validation to Network.framework, so the runtime cannot pin a leaf "
                + "certificate. Pinning is a WebTransportTLSCore-only API for direct callers.",
            evidence: [
                "WebTransportTLSCoreTests",
                "WebTransportPublicAPITests",
                "WebTransportPhase13Tests",
                "run-third-party-interop.sh three independent endpoint proof",
            ]
        ),
    ]

    /// True only when every requirement family is a full pass.
    ///
    /// This is a real check now that the status type can express `partial`,
    /// `notImplemented` and `unknown`: it is false as soon as any row records a
    /// gap. It still reports what the table *declares* rather than what a test run
    /// proved — `evidence` names the suites behind each row — so it must not be
    /// read as a CI result.
    public static var allPass: Bool {
        definitionOfDone.allSatisfy { $0.status == .pass && !$0.evidence.isEmpty && !$0.documentedBehavior.isEmpty }
    }
}
