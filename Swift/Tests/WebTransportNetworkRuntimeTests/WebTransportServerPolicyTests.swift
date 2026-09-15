import Foundation
import Testing
@testable import WebTransportNetworkRuntime

// Admission control and transport limits. The rate limiter is the part with real
// logic, so it is tested against a controlled clock rather than by sleeping:
// a wall-clock test of a refill rate is slow and flaky, and proves less.

@Test
func rateLimiterAllowsBurstThenThrottlesToTheConfiguredRate() throws {
    let policy = WebTransportAdmissionPolicy(
        maxConcurrentConnections: 16,
        maxAcceptedConnectionsPerSecond: 10,
        burstCapacity: 5
    )
    let limiter = try #require(ConnectionRateLimiter(policy: policy))
    let start = Date(timeIntervalSince1970: 1_000_000)

    // The bucket starts full, so exactly `burstCapacity` pass instantly.
    for index in 0..<5 {
        #expect(limiter.allow(now: start), "burst slot \(index) should be allowed")
    }
    #expect(!limiter.allow(now: start), "burst exhausted, further connections must be refused")

    // At 10/s, 100ms buys exactly one token.
    #expect(limiter.allow(now: start.addingTimeInterval(0.1)))
    #expect(!limiter.allow(now: start.addingTimeInterval(0.1)))

    // A long idle period must not accrue unlimited credit: refill is capped at
    // the burst ceiling, or a quiet listener would hand a peer an enormous burst.
    let later = start.addingTimeInterval(3_600)
    for _ in 0..<5 {
        #expect(limiter.allow(now: later))
    }
    #expect(!limiter.allow(now: later), "refill must saturate at burst capacity")
}

@Test
func rateLimiterIsAbsentWhenNoRateIsConfigured() {
    // No configured rate means no limiter at all, so the accept path pays
    // nothing for a feature the operator did not ask for.
    #expect(ConnectionRateLimiter(policy: .default) == nil)
    #expect(ConnectionRateLimiter(policy: WebTransportAdmissionPolicy(maxConcurrentConnections: 99)) == nil)
    #expect(ConnectionRateLimiter(policy: .publicFacing) != nil)
}

@Test
func admissionPolicyRejectsNonsensicalValues() {
    #expect(throws: Error.self) {
        try WebTransportAdmissionPolicy(maxConcurrentConnections: 0).validated()
    }
    #expect(throws: Error.self) {
        try WebTransportAdmissionPolicy(maxConcurrentConnections: -1).validated()
    }
    #expect(throws: Error.self) {
        try WebTransportAdmissionPolicy(
            maxConcurrentConnections: 16,
            maxAcceptedConnectionsPerSecond: 0
        ).validated()
    }
    #expect(throws: Error.self) {
        try WebTransportAdmissionPolicy(
            maxConcurrentConnections: 16,
            maxAcceptedConnectionsPerSecond: 10,
            burstCapacity: 0
        ).validated()
    }
    #expect(throws: Never.self) { try WebTransportAdmissionPolicy.default.validated() }
    #expect(throws: Never.self) { try WebTransportAdmissionPolicy.publicFacing.validated() }
}

@Test
func transportLimitsRejectNonsensicalValuesAndKeepHistoricalDefaults() throws {
    #expect(throws: Error.self) {
        try WebTransportTransportLimits(idleTimeoutMilliseconds: 0).validated()
    }
    #expect(throws: Error.self) {
        try WebTransportTransportLimits(initialMaxData: 0).validated()
    }
    #expect(throws: Error.self) {
        try WebTransportTransportLimits(initialMaxBidirectionalStreams: -1).validated()
    }

    // Adopting the type must not silently change what the runtime advertises;
    // these are the values that were hardcoded before it existed.
    let defaults = try WebTransportTransportLimits.default.validated()
    #expect(defaults.idleTimeoutMilliseconds == 30_000)
    #expect(defaults.initialMaxData == 1_048_576)
    #expect(defaults.initialMaxStreamDataBidirectionalLocal == 262_144)
    #expect(defaults.initialMaxStreamDataBidirectionalRemote == 262_144)
    #expect(defaults.initialMaxStreamDataUnidirectional == 262_144)
    #expect(defaults.initialMaxBidirectionalStreams == 16)
    #expect(defaults.initialMaxUnidirectionalStreams == 16)
    #expect(defaults.maxDatagramFrameSize == 65_535)
}

@Test
func listenerAcceptsConfiguredPoliciesAndStillServes() async throws {
    // The policies must reach the listener without breaking it.
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false,
        admission: WebTransportAdmissionPolicy(
            maxConcurrentConnections: 32,
            maxAcceptedConnectionsPerSecond: 50,
            burstCapacity: 100
        ),
        transportLimits: WebTransportTransportLimits(
            idleTimeoutMilliseconds: 15_000,
            initialMaxData: 2_097_152,
            initialMaxBidirectionalStreams: 32
        )
    )
    defer { server.shutdown() }
    let endpoint = try await server.waitForListening(timeoutMilliseconds: 5_000)
    #expect(endpoint.port != 0)
}

@Test
func invalidPoliciesFailListenerConstructionRatherThanBindingSilently() {
    #expect(throws: Error.self) {
        _ = try WebTransportQUICServer(
            endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
            admission: WebTransportAdmissionPolicy(maxConcurrentConnections: 0)
        )
    }
    #expect(throws: Error.self) {
        _ = try WebTransportQUICServer(
            endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
            transportLimits: WebTransportTransportLimits(idleTimeoutMilliseconds: -1)
        )
    }
}

// MARK: - Precedence between the legacy limit and an admission policy

/// `maxConcurrentConnections` predates the admission policy. An explicit value must
/// override the policy, and it must be validated on the same terms as the policy's own
/// field.
///
/// The override used to be gated on `admission == .default`, so a caller passing both a
/// policy and an explicit limit had the limit silently ignored — the policy's value won
/// with no diagnostic, and an out-of-range limit was neither applied nor refused.
@Test
func explicitConcurrencyLimitOverridesANonDefaultPolicy() throws {
    let endpoint = WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0)

    // A policy plus an explicit limit constructs, and the limit is applied. The
    // assertion is what makes this the precedence test: with the old
    // `admission == .default` gate the explicit 1 was ignored and the policy's
    // 256 was enforced instead.
    let overriding = try WebTransportQUICServer(
        endpoint: endpoint,
        maxConcurrentConnections: 1,
        authority: "localhost",
        localOnly: false,
        admission: .publicFacing
    )
    #expect(
        overriding.effectiveAdmissionPolicy.maxConcurrentConnections == 1,
        "an explicit limit must override a non-default policy"
    )
    overriding.shutdown()

    // An out-of-range explicit limit is refused rather than silently coerced to 1.
    for invalid in [0, -1] {
        #expect(throws: (any Error).self, "maxConcurrentConnections \(invalid) must be refused") {
            _ = try WebTransportQUICServer(
                endpoint: endpoint,
                maxConcurrentConnections: invalid,
                authority: "localhost",
                localOnly: false,
                admission: .publicFacing
            )
        }
    }

    // Leaving the limit at its default still lets the policy decide.
    let policyDefault = try WebTransportQUICServer(
        endpoint: endpoint,
        authority: "localhost",
        localOnly: false,
        admission: .publicFacing
    )
    #expect(
        policyDefault.effectiveAdmissionPolicy.maxConcurrentConnections == 256,
        "with no explicit limit the policy's own value must be enforced"
    )
    policyDefault.shutdown()
}

/// F-swift-architecture-05: `16` was used as the "argument not supplied"
/// sentinel, so an explicit `maxConcurrentConnections: 16` was indistinguishable
/// from the default and the policy's own limit silently won. An explicit value
/// must always win, whatever it is; `nil` is the only "not supplied".
@Test
func explicitConcurrencyLimitOfExactlyTheOldSentinelStillOverridesThePolicy() throws {
    let endpoint = WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0)

    let explicitSixteen = try WebTransportQUICServer(
        endpoint: endpoint,
        maxConcurrentConnections: 16,
        authority: "localhost",
        localOnly: false,
        admission: .publicFacing
    )
    defer { explicitSixteen.shutdown() }
    #expect(explicitSixteen.effectiveAdmissionPolicy.maxConcurrentConnections == 16)

    // Only the absence of the argument lets the policy decide.
    let policyDefault = try WebTransportQUICServer(
        endpoint: endpoint,
        authority: "localhost",
        localOnly: false,
        admission: .publicFacing
    )
    defer { policyDefault.shutdown() }
    #expect(policyDefault.effectiveAdmissionPolicy.maxConcurrentConnections == 256)
}
