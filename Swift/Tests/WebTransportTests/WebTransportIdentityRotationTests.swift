import Foundation
import Testing
import WebTransport

// Certificate rotation.
//
// The constraint driving this design was measured, not assumed: Network.framework
// builds a listener's parameters — including the TLS identity — once per
// listener, not once per connection. A probe logging each parameter build
// recorded one build across three connections. So a certificate cannot be
// swapped on a live listener, and rotation has to be a listener handover.
//
// These tests pin what an operator depends on: knowing when rotation is due, and
// the handover actually yielding a listener with a different certificate. They
// use the development identity because it is regenerated on every construction,
// which makes "the certificate changed" directly observable without reaching
// into runtime internals for certificate minting.

@Test
func listenerReportsCertificateExpirySoRotationCanBeScheduled() async throws {
    // Without an expiry an operator has no signal for when to rebind, and the
    // first symptom of an expired certificate is peers failing validation.
    let server = WebTransportServer(configuration: WebTransportServerConfiguration(
        authority: "localhost",
        localOnly: true
    ))
    let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
    defer { listener.shutdown() }

    let notAfter = try #require(listener.certificateNotAfter, "expiry must be readable")
    #expect(notAfter > Date(), "certificate must not already be expired")
    // The development certificate is minted with a 24-hour window.
    #expect(notAfter < Date().addingTimeInterval(48 * 3_600), "development certificate should be short-lived")
}

@Test
func rotationProducesAListenerPresentingADifferentCertificate() async throws {
    let server = WebTransportServer(configuration: WebTransportServerConfiguration(
        authority: "localhost",
        localOnly: true
    ))

    let original = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
    let originalFingerprint = original.certificateSHA256

    // Rebind on an ephemeral port: what is under test is that the replacement
    // presents a new identity, not that it reclaims the same port, which is
    // subject to the unbind window the API documents.
    let rotated = try await server.rotateIdentity(
        of: original,
        to: .developmentSelfSigned,
        on: WebTransportEndpoint(host: "127.0.0.1", port: 0),
        gracePeriodMilliseconds: 500
    )
    defer { rotated.shutdown() }

    #expect(rotated.certificateSHA256 != originalFingerprint, "rotation must change the presented certificate")
    #expect(rotated.localEndpoint.port != 0)
    #expect(rotated.certificateNotAfter != nil)
}

@Test
func rotationRetiresTheOldListenerBeforeReturning() async throws {
    let server = WebTransportServer(configuration: WebTransportServerConfiguration(
        authority: "localhost",
        localOnly: true
    ))
    let original = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))

    let rotated = try await server.rotateIdentity(
        of: original,
        to: .developmentSelfSigned,
        on: WebTransportEndpoint(host: "127.0.0.1", port: 0),
        gracePeriodMilliseconds: 300
    )
    defer { rotated.shutdown() }

    // The old listener must already be refusing, or a peer could still land on a
    // listener the operator believes is retired.
    await #expect(throws: Error.self) {
        _ = try await original.acceptSession()
    }
}
