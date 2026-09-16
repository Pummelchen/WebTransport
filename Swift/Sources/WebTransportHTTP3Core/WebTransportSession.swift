import Foundation
import WebTransportQUICCore

/// The mutable state behind ``WebTransportSessionManager``.
///
/// The manager's mutating methods live in sibling files, split by concern. A `private(set)` setter is
/// file-scoped, so a method moved to another file can no longer write the property it owns; the
/// properties it writes are therefore declared `public internal(set)`. `internal(set)` widens the
/// setter inside this module only, so an external consumer still sees a read-only property exactly as
/// `private(set)` gave them — SwiftPM's module boundary is the API boundary here. A reference-type
/// holder would instead have changed the copy semantics of this public `Sendable` struct: two copies
/// of the manager would share one mutable store, so a consumer reading a copy from another isolation
/// domain while the producer mutates it would be a data race. Keeping the storage on the value type
/// preserves the copy semantics the manager always had and needs no `@unchecked Sendable`.
public struct WebTransportSessionManager: Equatable, Sendable {
    public internal(set) var http3: HTTP3ConnectionState
    public internal(set) var sessionsByID: [WebTransportSessionID: WebTransportSession]
    public internal(set) var sessionIDsByRequestStreamID: [UInt64: WebTransportSessionID]
    public internal(set) var streamsByID: [UInt64: WebTransportStreamState]
    public internal(set) var streamIDsBySessionID: [WebTransportSessionID: Set<UInt64>]
    public internal(set) var bufferedStreamsByID: [UInt64: WebTransportStreamState]
    public internal(set) var bufferedStreamIDsBySessionID: [WebTransportSessionID: Set<UInt64>]
    public internal(set) var datagramsBySessionID: [WebTransportSessionID: [Data]]
    public internal(set) var flowControlStateBySessionID: [WebTransportSessionID: WebTransportFlowControlState]
    public internal(set) var receiveFlowControlStateBySessionID: [WebTransportSessionID: WebTransportFlowControlState]
    public internal(set) var blockedFlowCapsulesBySessionID: [WebTransportSessionID: [WebTransportFlowCapsule]]
    /// Largest DATAGRAM this endpoint will accept, matching what the QUIC layer
    /// advertised to the peer. Enforcing a smaller number here rejects peers that
    /// are honouring exactly what we told them they could send.
    public let maxDatagramFrameSize: Int
    /// Largest DATAGRAM this endpoint will attempt to send.
    ///
    /// Defaults to `min(maxDatagramFrameSize, 1200)`, which encodes two rules:
    /// never send more than this endpoint would itself accept, and never exceed
    /// the 1200 bytes a QUIC path is guaranteed to carry (RFC 9000 section 14).
    ///
    /// It is separate from the receive ceiling because the two are not the same
    /// question. A peer may legitimately advertise a large receive limit, but a
    /// QUIC DATAGRAM cannot be fragmented, so anything above the path MTU is
    /// silently undeliverable. Bounding sends turns that silent loss into an
    /// immediate, explicit error.
    public let maxSendableDatagramFrameSize: Int
    public let maxDatagramReceiveBufferBytes: Int
    public let maxStreamReceiveBufferBytes: Int
    public let maxBufferedStreamsPerSession: Int
    public let maxBufferedDatagramsPerSession: Int
    public let maxBufferedSessions: Int
    public let settingsValidation: HTTP3WebTransportSettingsValidation
    /// How many terminated sessions keep their tombstone.
    ///
    /// A terminated session is retained so that late activity on it reports
    /// "session gone" rather than "unknown", which is a materially better error.
    /// The retention has to be bounded, though: the tombstone holds the peer's
    /// own authority and path strings, a CONNECT field section may be up to
    /// 16 KB, and a peer can open and close sessions on one connection
    /// indefinitely. Unbounded retention is remotely triggerable memory growth.
    ///
    /// Beyond this many, the oldest tombstone is dropped and activity on it
    /// degrades to "unknown session", which is a safe answer.
    public let maxRetainedClosedSessions: Int
    /// How many terminated streams keep their tombstone, for the same reason.
    public let maxRetainedClosedStreams: Int

    var datagramPayloadBytesBySessionID: [WebTransportSessionID: Int]
    var closedStreamSessionIDsByStreamID: [UInt64: WebTransportSessionID]
    var requestStreamIDsClosedByReceivedCloseCapsule: Set<UInt64>
    /// Tombstone insertion order, oldest first, so eviction is deterministic.
    var closedSessionOrder: [WebTransportSessionID]
    var closedStreamOrder: [UInt64]
    /// How many leading entries of ``closedStreamOrder`` have been evicted.
    var closedStreamHead: Int
    /// Membership for the tombstones still retained, so a duplicate close is
    /// recognised without scanning ``closedStreamOrder``.
    var retainedClosedStreamIDs: Set<UInt64>

    /// How many elements ``recordClosedStream(_:)`` moved while evicting.
    ///
    /// A cost probe for the regression test in `WebTransportSessionTests`: a
    /// stream close must not shift the whole retention window.
    var closedStreamTombstoneMoves = 0

    public init(
        http3: HTTP3ConnectionState,
        maxStreamReceiveBufferBytes: Int = 64 * 1024,
        maxDatagramFrameSize: Int = 1_200,
        maxSendableDatagramFrameSize: Int? = nil,
        maxDatagramReceiveBufferBytes: Int = 64 * 1024,
        maxBufferedStreamsPerSession: Int = 64,
        maxBufferedDatagramsPerSession: Int = 64,
        maxBufferedSessions: Int = 64,
        maxRetainedClosedSessions: Int = 256,
        maxRetainedClosedStreams: Int = 4_096,
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft16Strict
    ) {
        self.http3 = http3
        self.sessionsByID = [:]
        self.sessionIDsByRequestStreamID = [:]
        self.streamsByID = [:]
        self.streamIDsBySessionID = [:]
        self.bufferedStreamsByID = [:]
        self.bufferedStreamIDsBySessionID = [:]
        self.datagramsBySessionID = [:]
        self.flowControlStateBySessionID = [:]
        self.receiveFlowControlStateBySessionID = [:]
        self.blockedFlowCapsulesBySessionID = [:]
        self.maxDatagramFrameSize = maxDatagramFrameSize
        self.maxSendableDatagramFrameSize =
            maxSendableDatagramFrameSize
            ?? min(maxDatagramFrameSize, 1_200)
        self.maxDatagramReceiveBufferBytes = maxDatagramReceiveBufferBytes
        self.maxStreamReceiveBufferBytes = maxStreamReceiveBufferBytes
        self.maxBufferedStreamsPerSession = maxBufferedStreamsPerSession
        self.maxBufferedDatagramsPerSession = maxBufferedDatagramsPerSession
        self.maxBufferedSessions = maxBufferedSessions
        self.settingsValidation = settingsValidation
        self.maxRetainedClosedSessions = max(0, maxRetainedClosedSessions)
        self.maxRetainedClosedStreams = max(0, maxRetainedClosedStreams)
        self.datagramPayloadBytesBySessionID = [:]
        self.closedStreamSessionIDsByStreamID = [:]
        self.requestStreamIDsClosedByReceivedCloseCapsule = []
        self.closedSessionOrder = []
        self.closedStreamOrder = []
        self.closedStreamHead = 0
        self.retainedClosedStreamIDs = []
    }
}
