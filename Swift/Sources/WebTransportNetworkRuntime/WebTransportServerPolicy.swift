import Foundation
import Synchronization

/// QUIC transport limits advertised to peers.
///
/// These were previously fixed in the runtime, which meant an operator could not
/// tune the server for their workload without forking. The defaults are the
/// values the runtime has always used, so adopting this type changes nothing on
/// its own.
///
/// Every field is a resource an unauthenticated peer can cause the server to
/// commit, so the ceiling on memory per connection is roughly
/// `initialMaxData` plus `initialMaxBidirectionalStreams` multiplied by
/// `initialMaxStreamDataBidirectionalRemote`. Raising throughput limits without
/// lowering `maxConcurrentConnections` raises the worst-case footprint with it.
public struct WebTransportTransportLimits: Equatable, Sendable {
    /// Idle time before the connection is closed. Bounds how long an abandoned
    /// connection holds resources.
    public var idleTimeoutMilliseconds: Int
    /// Connection-level flow-control window.
    public var initialMaxData: Int
    public var initialMaxStreamDataBidirectionalLocal: Int
    public var initialMaxStreamDataBidirectionalRemote: Int
    public var initialMaxStreamDataUnidirectional: Int
    /// Concurrent streams a peer may open. Each one costs buffer space.
    public var initialMaxBidirectionalStreams: Int
    public var initialMaxUnidirectionalStreams: Int
    public var maxDatagramFrameSize: Int

    public init(
        idleTimeoutMilliseconds: Int = 30_000,
        initialMaxData: Int = 1_048_576,
        initialMaxStreamDataBidirectionalLocal: Int = 262_144,
        initialMaxStreamDataBidirectionalRemote: Int = 262_144,
        initialMaxStreamDataUnidirectional: Int = 262_144,
        initialMaxBidirectionalStreams: Int = 16,
        initialMaxUnidirectionalStreams: Int = 16,
        maxDatagramFrameSize: Int = 65_535
    ) {
        self.idleTimeoutMilliseconds = idleTimeoutMilliseconds
        self.initialMaxData = initialMaxData
        self.initialMaxStreamDataBidirectionalLocal = initialMaxStreamDataBidirectionalLocal
        self.initialMaxStreamDataBidirectionalRemote = initialMaxStreamDataBidirectionalRemote
        self.initialMaxStreamDataUnidirectional = initialMaxStreamDataUnidirectional
        self.initialMaxBidirectionalStreams = initialMaxBidirectionalStreams
        self.initialMaxUnidirectionalStreams = initialMaxUnidirectionalStreams
        self.maxDatagramFrameSize = maxDatagramFrameSize
    }

    /// The values the runtime used before these became configurable.
    public static let `default` = WebTransportTransportLimits()

    func validated() throws -> WebTransportTransportLimits {
        guard idleTimeoutMilliseconds > 0 else {
            throw WebTransportNetworkRuntimeError.invalidTransport("idle timeout must be positive")
        }
        guard initialMaxData > 0, maxDatagramFrameSize > 0 else {
            throw WebTransportNetworkRuntimeError.invalidTransport("transport limits must be positive")
        }
        guard initialMaxBidirectionalStreams >= 0, initialMaxUnidirectionalStreams >= 0 else {
            throw WebTransportNetworkRuntimeError.invalidTransport("stream limits must not be negative")
        }
        return self
    }
}

/// What the listener will accept before it starts refusing.
///
/// A publicly reachable listener needs a ceiling it enforces itself. Without one
/// the only limit is how fast a peer can open connections, and each accepted
/// connection commits the memory described by ``WebTransportTransportLimits``
/// before the peer has authenticated anything.
public struct WebTransportAdmissionPolicy: Equatable, Sendable {
    /// Connections that may be in flight at once. Further connections are
    /// refused until one is served or times out.
    public var maxConcurrentConnections: Int

    /// Ceiling on newly accepted connections per second, or nil for no limit.
    ///
    /// Distinct from ``maxConcurrentConnections``: a peer that connects and
    /// disconnects rapidly never raises the concurrent count but can still make
    /// the server do handshake work indefinitely. Enforced as a token bucket, so
    /// a burst up to ``burstCapacity`` passes and the sustained rate is capped.
    public var maxAcceptedConnectionsPerSecond: Int?

    /// Burst allowance for the rate limit. Defaults to one second's worth.
    public var burstCapacity: Int?

    public init(
        maxConcurrentConnections: Int = 16,
        maxAcceptedConnectionsPerSecond: Int? = nil,
        burstCapacity: Int? = nil
    ) {
        self.maxConcurrentConnections = maxConcurrentConnections
        self.maxAcceptedConnectionsPerSecond = maxAcceptedConnectionsPerSecond
        self.burstCapacity = burstCapacity
    }

    public static let `default` = WebTransportAdmissionPolicy()

    /// Sane starting point for a publicly reachable listener.
    ///
    /// Not the default: raising limits changes resource consumption, which is an
    /// operator's decision to make deliberately rather than inherit.
    public static let publicFacing = WebTransportAdmissionPolicy(
        maxConcurrentConnections: 256,
        maxAcceptedConnectionsPerSecond: 100,
        burstCapacity: 200
    )

    func validated() throws -> WebTransportAdmissionPolicy {
        guard maxConcurrentConnections > 0 else {
            throw WebTransportNetworkRuntimeError.invalidTransport("maxConcurrentConnections must be positive")
        }
        if let rate = maxAcceptedConnectionsPerSecond, rate <= 0 {
            throw WebTransportNetworkRuntimeError.invalidTransport("connection rate limit must be positive")
        }
        if let burst = burstCapacity, burst <= 0 {
            throw WebTransportNetworkRuntimeError.invalidTransport("burst capacity must be positive")
        }
        return self
    }
}

/// Token bucket governing how fast connections may be accepted.
///
/// Refills continuously from elapsed time rather than on a timer, so it needs no
/// background task and cannot drift: a listener that is idle for a minute is not
/// owed a minute of accumulated tokens beyond the burst ceiling.
final class ConnectionRateLimiter: @unchecked Sendable {
    private struct State {
        var tokens: Double
        var lastRefill: Date
    }

    private let ratePerSecond: Double
    private let capacity: Double
    private let state: Mutex<State>

    init?(policy: WebTransportAdmissionPolicy) {
        guard let rate = policy.maxAcceptedConnectionsPerSecond else {
            return nil
        }
        self.ratePerSecond = Double(rate)
        self.capacity = Double(policy.burstCapacity ?? rate)
        self.state = Mutex(State(tokens: Double(policy.burstCapacity ?? rate), lastRefill: Date()))
    }

    /// Consumes one token. Returns false when the caller should refuse the
    /// connection rather than queue it.
    func allow(now: Date = Date()) -> Bool {
        state.withLock { state in
            let elapsed = max(0, now.timeIntervalSince(state.lastRefill))
            state.tokens = min(capacity, state.tokens + elapsed * ratePerSecond)
            state.lastRefill = now
            guard state.tokens >= 1 else {
                return false
            }
            state.tokens -= 1
            return true
        }
    }
}
