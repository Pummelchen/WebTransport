import Foundation
import Security
import Testing
@testable import WebTransportNetworkRuntime

/// WT-261: which name a server's certificate is checked against.
///
/// A certificate proves a NAME, and `authority` is documented as "The expected `:authority` value on the
/// extended CONNECT request". Until this fix the QUIC layer validated the certificate against the host it
/// dialled instead, so reaching a server by address for a name its certificate carries failed the handshake
/// with a TLS `bad_certificate` alert — measured against the VPS peer, which is why the interop runner had
/// to dial the certificate's own name.
///
/// The fix is a decision plus a mechanism: `certificateName` decides whether the configured name differs from
/// the dialled one (tested here, as a pure function), and the certificate validator installed for that name
/// runs the platform's own SSL policy against the platform's own trust anchors. The anchors are deliberately
/// not touched, so this narrows nothing and widens nothing about *who* is trusted; only *which name* has to
/// be proven changes.
///
/// Two properties matter enough to pin:
///
/// 1. Extraction has to survive the forms an authority really takes — an IPv6 literal is bracketed and its
///    colons are not a port, so a naive "split on the last colon" turns `[::1]:443` into `::1` (right) and
///    `::1` into `::` (wrong).
/// 2. There is no override when the two names already agree, or under the local development policy, which
///    has no verification to name. Installing a validator in those cases would replace the framework's
///    correct check with a redundant one for no reason.
@Suite("WT-261 authority verification")
struct WebTransportAuthorityVerificationTests {
    @Test("the host is extracted from every authority form")
    func authorityHostExtraction() {
        #expect(InteroperableQUICAuthority.host(of: "example.com") == "example.com")
        #expect(InteroperableQUICAuthority.host(of: "example.com:443") == "example.com")
        #expect(InteroperableQUICAuthority.host(of: "[::1]:443") == "::1")
        #expect(InteroperableQUICAuthority.host(of: "[2001:db8::1]:8443") == "2001:db8::1")
        // A bare IPv6 literal has several colons and no port, so the last one is not a separator.
        #expect(InteroperableQUICAuthority.host(of: "::1") == "::1")
        #expect(InteroperableQUICAuthority.host(of: "2001:db8::1") == "2001:db8::1")
        #expect(InteroperableQUICAuthority.host(of: "127.0.0.1:54001") == "127.0.0.1")
        #expect(InteroperableQUICAuthority.host(of: "  example.com:443  ") == "example.com")
    }

    @Test("a differing authority names the certificate; an agreeing one leaves the framework's check in place")
    func certificateNameFollowsTheAuthority() {
        let endpoint = WebTransportNetworkEndpoint(host: "127.0.0.1", port: 54001)
        // Dialling the address for a name the certificate carries is the WT-261 case: the name is what has
        // to be verified.
        #expect(
            WebTransportQUICPeerTrustPolicy.systemTrust.certificateName(
                endpoint: endpoint,
                authority: "pummelchen.91.99.176.243.nip.io"
            ) == "pummelchen.91.99.176.243.nip.io"
        )
        // An authority with a port names the same host.
        #expect(
            WebTransportQUICPeerTrustPolicy.systemTrust.certificateName(
                endpoint: endpoint,
                authority: "pummelchen.91.99.176.243.nip.io:443"
            ) == "pummelchen.91.99.176.243.nip.io"
        )
        // Agreement, case-insensitively: nothing to override.
        #expect(
            WebTransportQUICPeerTrustPolicy.systemTrust.certificateName(
                endpoint: WebTransportNetworkEndpoint(host: "Example.com", port: 443),
                authority: "example.com"
            ) == nil
        )
        // No authority at all: the dialled host is the name.
        #expect(
            WebTransportQUICPeerTrustPolicy.systemTrust.certificateName(
                endpoint: WebTransportNetworkEndpoint(host: "pummelchen.91.99.176.243.nip.io", port: 443),
                authority: nil
            ) == nil
        )
        #expect(
            WebTransportQUICPeerTrustPolicy.systemTrust.certificateName(
                endpoint: endpoint,
                authority: "127.0.0.1:54001"
            ) == nil
        )
        // The local development policy disables verification, so there is no name to verify.
        #expect(
            WebTransportQUICPeerTrustPolicy.localDevelopmentSelfSigned.certificateName(
                endpoint: endpoint,
                authority: "pummelchen.91.99.176.243.nip.io"
            ) == nil
        )
        // An empty authority falls back to the dialled host rather than naming nothing.
        #expect(
            WebTransportQUICPeerTrustPolicy.systemTrust.certificateName(
                endpoint: endpoint,
                authority: ""
            ) == nil
        )
    }

    @Test("the runtime configuration selects the named check only when the names differ")
    func runtimeConfigurationSelectsTheNamedCheck() throws {
        let endpoint = WebTransportNetworkEndpoint(host: "127.0.0.1", port: 54001)
        guard
            case .systemTrustForName(let name) = try WebTransportQUICPeerTrustPolicy.systemTrust.runtimeConfiguration(
                endpoint: endpoint,
                authority: "pummelchen.91.99.176.243.nip.io"
            )
        else {
            Issue.record("a differing authority must select the named verification")
            return
        }
        #expect(name == "pummelchen.91.99.176.243.nip.io")

        guard
            case .systemTrust = try WebTransportQUICPeerTrustPolicy.systemTrust.runtimeConfiguration(
                endpoint: endpoint,
                authority: nil
            )
        else {
            Issue.record("an agreeing authority must leave the framework's own validation in place")
            return
        }

        guard
            case .localLoopbackDevelopmentSelfSigned =
                try WebTransportQUICPeerTrustPolicy.localDevelopmentSelfSigned.runtimeConfiguration(
                    endpoint: endpoint,
                    authority: nil
                )
        else {
            Issue.record("the local development policy must keep its self-signed bypass")
            return
        }
    }

    @Test("local development trust is still refused for a non-loopback endpoint")
    func localDevelopmentTrustStaysLoopbackOnly() {
        #expect(throws: WebTransportNetworkRuntimeError.self) {
            _ = try WebTransportQUICPeerTrustPolicy.localDevelopmentSelfSigned.runtimeConfiguration(
                endpoint: WebTransportNetworkEndpoint(host: "pummelchen.91.99.176.243.nip.io", port: 443),
                authority: nil
            )
        }
    }

    /// The security property, stated as a test: naming the right name is not enough.
    ///
    /// The override exists to change *which name* is checked, and the surest way to get that wrong would be to
    /// accept a certificate whose name matches without evaluating the chain at all. The fixture below is a
    /// self-signed leaf carrying `DNS:localhost`, so a name that the certificate DOES cover must still be refused,
    /// because the platform trust store holds no anchor for it. A future change that weakened the anchors — or that
    /// skipped evaluation on a name match — fails here.
    ///
    /// It is also the ownership check for `sec_trust_copy_ref`: the same `sec_trust_t` is evaluated repeatedly, so
    /// an over-release of the copied reference is a crash or an ASan report rather than a silent leak.
    @Test("a matching name is not accepted without a trusted anchor")
    func nameMatchIsNotEnoughWithoutATrustedAnchor() throws {
        let url = try #require(
            Bundle.module.url(forResource: "libressl-rsa-identity", withExtension: "p12"),
            "missing fixture libressl-rsa-identity.p12; is it declared in Package.swift resources?"
        )
        let resolved = try ServerIdentityResolver.resolve(
            .pkcs12(data: try Data(contentsOf: url), passphrase: "pw"),
            endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433),
            authority: "localhost",
            localOnly: false
        )
        let certificate = try #require(
            SecCertificateCreateWithData(nil, resolved.leafCertificateDER as CFData),
            "the fixture leaf certificate could not be decoded"
        )
        var created: SecTrust?
        // SAFETY: `SecTrustCreateWithCertificates` follows the Create rule and writes a retained `SecTrust` to the
        // out-parameter, which `created` owns; the leaf certificate and the policy it is created with outlive it.
        let status = unsafe SecTrustCreateWithCertificates(certificate, SecPolicyCreateSSL(true, nil), &created)
        #expect(status == errSecSuccess)
        let trust = try #require(created)
        let secTrust = try #require(sec_trust_create(trust))

        // `localhost` is in the fixture's subjectAltName, and it is still refused: no anchor trusts this leaf.
        #expect(InteroperableQUICCertificateVerification.isValid(secTrust, forName: "localhost") == false)
        // And the same trust, evaluated again, reaches the same answer rather than a use-after-free.
        #expect(InteroperableQUICCertificateVerification.isValid(secTrust, forName: "localhost") == false)
        #expect(
            InteroperableQUICCertificateVerification.isValid(secTrust, forName: "not-the-name.example") == false
        )
    }
}
