import Foundation
import Network
import Testing
@testable import WebTransportNetworkRuntime

/// WT-185: a connection the transport failed to establish is named, not rethrown raw.
///
/// `NetworkConnection.State.failed` carries the framework's own error, and on a loaded
/// host that is a transient POSIX condition rather than anything about the endpoint.
/// Before this case existed it propagated out of `connectSession` and `acceptSession`
/// verbatim, so `listenerServesMoreSequentialSessionsThanTheDefaultCeiling` failed under
/// Thread Sanitizer with a bare `POSIXErrorCode(rawValue: 50)` and, in a different run,
/// `(rawValue: 57)`. Two errnos is why the retry predicate is a class of conditions
/// rather than a single code: a fix that special-cased `ENETDOWN` would have missed
/// `ENOTCONN`.
@Test
func establishmentFailureNamesTransientTransportConditions() {
    for code in [
        POSIXErrorCode.ENETDOWN, .ENOTCONN, .ENETUNREACH, .EHOSTUNREACH, .EADDRNOTAVAIL,
    ] {
        let error = WebTransportNetworkRuntimeError.connectionEstablishmentFailed(
            role: "client",
            domain: NSPOSIXErrorDomain,
            code: Int(code.rawValue)
        )
        #expect(error.isTransientEstablishmentFailure, "\(code) is a transient local-stack condition")
    }
}

/// The conditions a retry must NOT cover.
///
/// This is the guard that keeps the WT-185 retry from swallowing the defect the listener
/// test exists to catch. Issue #23 — a listener that stopped accepting once it had served
/// `maxConcurrentConnections` sessions — never completes a handshake, so a round against
/// one fails as a `timeout` after the configured deadline. If `timeout` ever became
/// retryable the test would quietly retry the very regression it guards.
@Test
func establishmentFailureDoesNotCoverTheDefectItGuards() {
    #expect(!WebTransportNetworkRuntimeError.timeout(5_000).isTransientEstablishmentFailure)

    // A peer that refuses or resets a connection, or a permission failure, is a different
    // and meaningful condition: retrying it would turn "that address is wrong" into a
    // slow failure instead of a fast, accurate one.
    for code in [POSIXErrorCode.ECONNREFUSED, .ECONNRESET, .EPERM] {
        let error = WebTransportNetworkRuntimeError.connectionEstablishmentFailed(
            role: "client",
            domain: NSPOSIXErrorDomain,
            code: Int(code.rawValue)
        )
        #expect(!error.isTransientEstablishmentFailure, "\(code) must not be retried")
    }

    // A framework error that is not POSIX is not one of these conditions either, whatever
    // its code. Only the named transient POSIX set is retryable.
    let nonPOSIX = WebTransportNetworkRuntimeError.connectionEstablishmentFailed(
        role: "server",
        domain: NSURLErrorDomain,
        code: Int(POSIXErrorCode.ENETDOWN.rawValue)
    )
    #expect(!nonPOSIX.isTransientEstablishmentFailure)

    // The cases that were already named are not establishment failures.
    #expect(
        !WebTransportNetworkRuntimeError.peerControlStreamNotDelivered(role: "client", timeoutMilliseconds: 5_000)
            .isTransientEstablishmentFailure)
    #expect(
        !WebTransportNetworkRuntimeError.peerClosedStreamWithoutData(streamID: 4)
            .isTransientEstablishmentFailure)
}

/// WT-221: a control stream that never arrives is named, and not as a plain timeout.
///
/// The loss is in the transport's stream delivery on a saturated receiver: the
/// peer sent its control stream and nothing of it arrived, so both ends wait for
/// each other. The runtime cannot see that from any other signal — no stream
/// arrives to prove one was dropped — so the only honest report is the deadline
/// expiring, and the caller's remedy is a fresh connection, which the error's
/// documentation carries. The loss is not resented, so a longer deadline cannot
/// recover it, and this test pins the classification the caller decides on rather
/// than a duration.
@Test
func peerControlStreamThatNeverArrivesIsNamedRatherThanATimeout() async throws {
    let collector = InteroperableQUICInboundStreamCollector()
    do {
        _ = try await InteroperableQUICHelpers.readPeerControlStream(
            from: collector,
            role: "client",
            timeoutMilliseconds: 5
        )
        Issue.record("a collector that never sees a stream must not return control bytes")
    } catch let error as WebTransportNetworkRuntimeError {
        #expect(error == .peerControlStreamNotDelivered(role: "client", timeoutMilliseconds: 5))
        #expect(!error.description.contains("timed out"), "the cause is not a slow peer")
        #expect(error.description.contains("retried"), "the remedy is a fresh connection")
    } catch {
        Issue.record("expected the named runtime error, got \(error)")
    }
}

/// The framework's own domain and code survive the translation, so a failure stays
/// diagnosable from the error alone rather than only from a debug log.
@Test
func establishmentFailureKeepsTheFrameworkError() {
    let code = Int(POSIXErrorCode.ENETDOWN.rawValue)
    let error = WebTransportNetworkRuntimeError.connectionEstablishmentFailed(
        role: "client",
        domain: NSPOSIXErrorDomain,
        code: code
    )
    #expect(error == .connectionEstablishmentFailed(role: "client", domain: NSPOSIXErrorDomain, code: code))
    #expect(error.description.contains("client"))
    #expect(error.description.contains(NSPOSIXErrorDomain))
    #expect(error.description.contains("\(code)"))
    // The wording must hold for either role: `waitForReady` serves the client's connect
    // and the server's accept, and for the server the peer did reach the endpoint.
    #expect(
        WebTransportNetworkRuntimeError.connectionEstablishmentFailed(
            role: "server", domain: NSPOSIXErrorDomain, code: code
        ).description.contains("server"))
}

/// The framework's POSIX errors bridge under their own domain, and the runtime normalises.
///
/// This pins the fact the whole retry rests on, and it is **measured rather than assumed**:
/// `NWError.posix(.ENETDOWN)` bridges to `NSError` under `"Network.NWError"`, **not**
/// `NSPOSIXErrorDomain`. A predicate that read the bridged domain would therefore never
/// match a real failure — which is exactly what the first version of this fix did, making
/// the retry inert while the suite stayed green. `establishmentFailure` unwraps the
/// `NWError` case for that reason, and the first assertion here is what would catch the
/// framework changing its bridging under us.
@Test
func posixNetworkErrorsAreNormalisedFromTheFrameworkError() {
    let posixError = NWError.posix(.ENETDOWN)
    let bridged = posixError as NSError
    #expect(bridged.domain == "Network.NWError")
    #expect(bridged.code == Int(POSIXErrorCode.ENETDOWN.rawValue))

    // The translation is what makes the predicate reachable for a real failure.
    guard
        case .connectionEstablishmentFailed(let role, let domain, let code) =
            InteroperableQUICHelpers.establishmentFailure(role: "client", error: posixError)
    else {
        Issue.record("a POSIX framework error should be named as an establishment failure")
        return
    }
    #expect(role == "client")
    #expect(domain == NSPOSIXErrorDomain)
    #expect(code == Int(POSIXErrorCode.ENETDOWN.rawValue))
    #expect(
        InteroperableQUICHelpers.establishmentFailure(role: "client", error: posixError)
            .isTransientEstablishmentFailure
    )

    // An error that is not a POSIX condition keeps its own domain rather than being forced
    // into the POSIX one.
    let notPOSIX = InteroperableQUICHelpers.establishmentFailure(role: "client", error: URLError(.timedOut))
    #expect(!notPOSIX.isTransientEstablishmentFailure)
}

/// The same bridging trap in the older predicate, which made its retry dead code.
///
/// `openBidirectionalStream` retries a stream open while the connection reports itself not
/// yet connected. That branch was unreachable for a real failure: the check read the
/// `NSError` domain, and `NWError.posix` does not bridge under `NSPOSIXErrorDomain`. This
/// pins the predicate against the error type the runtime actually receives.
@Test
func transientNotConnectedRecognisesRealFrameworkErrors() {
    #expect(InteroperableQUICHelpers.isTransientNotConnected(NWError.posix(.ENOTCONN)))
    #expect(!InteroperableQUICHelpers.isTransientNotConnected(NWError.posix(.ENETDOWN)))
    #expect(!InteroperableQUICHelpers.isTransientNotConnected(NWError.posix(.ECONNREFUSED)))
    // The plain POSIX form keeps working, so the fix is an addition rather than a swap.
    #expect(InteroperableQUICHelpers.isTransientNotConnected(POSIXError(.ENOTCONN)))
}
