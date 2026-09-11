import CryptoKit
import Foundation
import Security
import Testing
@testable import WebTransportNetworkRuntime
import WebTransportQUICCore

// MARK: - Host classification

@Test
func loopbackClassificationAcceptsLoopbackFormsAndRejectsRoutableHosts() {
    for host in ["127.0.0.1", "127.1.2.3", "localhost", "LOCALHOST", "::1", "[::1]", "0:0:0:0:0:0:0:1"] {
        #expect(LoopbackHost.isLoopback(host), "expected \(host) to be loopback")
    }
    for host in ["0.0.0.0", "128.0.0.1", "10.0.0.1", "192.168.1.10", "example.com", "", "126.255.255.255"] {
        #expect(!LoopbackHost.isLoopback(host), "expected \(host) to be non-loopback")
    }
}

@Test
func ipv4ParserRejectsAmbiguousAndMalformedLiterals() {
    #expect(IPv4.parse("127.0.0.1") == [127, 0, 0, 1])
    #expect(IPv4.parse("0.0.0.0") == [0, 0, 0, 0])
    #expect(IPv4.parse("255.255.255.255") == [255, 255, 255, 255])

    // Leading zeros are octal in some resolvers; refuse rather than guess.
    #expect(IPv4.parse("127.0.0.01") == nil)
    #expect(IPv4.parse("010.0.0.1") == nil)

    #expect(IPv4.parse("256.0.0.1") == nil)
    #expect(IPv4.parse("127.0.0") == nil)
    #expect(IPv4.parse("127.0.0.1.5") == nil)
    #expect(IPv4.parse("127.0.0.") == nil)
    #expect(IPv4.parse("127.0.0.x") == nil)
    #expect(IPv4.parse("") == nil)
}

// MARK: - Development identity is loopback-only

@Test
func developmentIdentityIsRefusedOnRoutableBindAddresses() {
    for host in ["0.0.0.0", "192.168.1.10", "example.com", "203.0.113.7"] {
        #expect(throws: Error.self, "expected \(host) to be refused") {
            _ = try ServerIdentityResolver.resolve(
                .developmentSelfSigned,
                endpoint: WebTransportNetworkEndpoint(host: host, port: 4433),
                authority: "example.com",
                localOnly: false
            )
        }
    }
}

@Test
func developmentIdentityIsAllowedOnLoopbackAndWhenLocalOnly() throws {
    for host in ["127.0.0.1", "localhost", "::1"] {
        let resolved = try ServerIdentityResolver.resolve(
            .developmentSelfSigned,
            endpoint: WebTransportNetworkEndpoint(host: host, port: 4433),
            authority: "localhost",
            localOnly: false
        )
        #expect(resolved.certificateSHA256.count == 32)
        #expect(!resolved.leafCertificateDER.isEmpty)
    }

    // localOnly binds cannot reach the network regardless of the host string.
    let resolved = try ServerIdentityResolver.resolve(
        .developmentSelfSigned,
        endpoint: WebTransportNetworkEndpoint(host: "0.0.0.0", port: 4433),
        authority: "localhost",
        localOnly: true
    )
    #expect(resolved.certificateSHA256.count == 32)
}

@Test
func developmentCertificateIsRegeneratedPerResolution() throws {
    let endpoint = WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433)
    let first = try ServerIdentityResolver.resolve(
        .developmentSelfSigned, endpoint: endpoint, authority: "localhost", localOnly: false
    )
    let second = try ServerIdentityResolver.resolve(
        .developmentSelfSigned, endpoint: endpoint, authority: "localhost", localOnly: false
    )
    // Documents the instability that makes the development certificate
    // unusable as a pin, which is why it is refused off loopback.
    #expect(first.certificateSHA256 != second.certificateSHA256)
}

// MARK: - Injected identities

/// Builds a throwaway P-256 certificate/key pair in the same DER form a caller
/// would load from disk, so the injection path is exercised end to end.
private func makeInjectableIdentityMaterial(
    commonName: String = "webtransport.test"
) throws -> (chainDER: [Data], privateKeyDER: Data) {
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecAttrIsPermanent: false,
    ]
    var keyError: Unmanaged<CFError>?
    guard let privateKey = unsafe SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) else {
        throw WebTransportNetworkRuntimeError.invalidTransport("test key generation failed")
    }
    // No `unsafe` marker here: passing nil for the error out-parameter means
    // these calls perform no unsafe pointer operation.
    guard let publicKey = SecKeyCopyPublicKey(privateKey),
        let publicKeyDER = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
        let privateKeyDER = SecKeyCopyExternalRepresentation(privateKey, nil) as Data?
    else {
        throw WebTransportNetworkRuntimeError.invalidTransport("test key export failed")
    }

    let certificateDER = try SelfSignedCertificate.make(
        privateKey: privateKey,
        p256PublicKeyDER: publicKeyDER,
        commonName: commonName,
        dnsNames: [commonName],
        ipAddresses: []
    )
    return ([certificateDER], privateKeyDER)
}

@Test
func injectedCertificateChainIsAcceptedOnRoutableBindAddresses() throws {
    let material = try makeInjectableIdentityMaterial()

    // The whole point of CERT-01: a real identity must work off loopback.
    let resolved = try ServerIdentityResolver.resolve(
        .certificateChain(
            chainDER: material.chainDER,
            privateKeyDER: material.privateKeyDER,
            keyKind: .ellipticCurveP256
        ),
        endpoint: WebTransportNetworkEndpoint(host: "0.0.0.0", port: 443),
        authority: "webtransport.test",
        localOnly: false
    )
    #expect(resolved.leafCertificateDER == material.chainDER[0])
    #expect(resolved.certificateSHA256.count == 32)
}

@Test
func injectedCertificateFingerprintIsStableAcrossResolutions() throws {
    let material = try makeInjectableIdentityMaterial()
    let source = WebTransportServerIdentity.certificateChain(
        chainDER: material.chainDER,
        privateKeyDER: material.privateKeyDER,
        keyKind: .ellipticCurveP256
    )
    let endpoint = WebTransportNetworkEndpoint(host: "0.0.0.0", port: 443)

    let first = try ServerIdentityResolver.resolve(
        source, endpoint: endpoint, authority: "webtransport.test", localOnly: false
    )
    let second = try ServerIdentityResolver.resolve(
        source, endpoint: endpoint, authority: "webtransport.test", localOnly: false
    )
    // Unlike the development certificate, an injected identity survives restarts.
    #expect(first.certificateSHA256 == second.certificateSHA256)
}

@Test
func injectedIdentityRejectsMalformedMaterial() throws {
    let material = try makeInjectableIdentityMaterial()
    let endpoint = WebTransportNetworkEndpoint(host: "0.0.0.0", port: 443)

    // Empty chain.
    #expect(throws: Error.self) {
        _ = try ServerIdentityResolver.resolve(
            .certificateChain(chainDER: [], privateKeyDER: material.privateKeyDER, keyKind: .ellipticCurveP256),
            endpoint: endpoint, authority: "webtransport.test", localOnly: false
        )
    }
    // Empty key.
    #expect(throws: Error.self) {
        _ = try ServerIdentityResolver.resolve(
            .certificateChain(chainDER: material.chainDER, privateKeyDER: Data(), keyKind: .ellipticCurveP256),
            endpoint: endpoint, authority: "webtransport.test", localOnly: false
        )
    }
    // Certificate bytes that are not DER.
    #expect(throws: Error.self) {
        _ = try ServerIdentityResolver.resolve(
            .certificateChain(
                chainDER: [Data([0x00, 0x01, 0x02])],
                privateKeyDER: material.privateKeyDER,
                keyKind: .ellipticCurveP256
            ),
            endpoint: endpoint, authority: "webtransport.test", localOnly: false
        )
    }
}

@Test
func undersizedRSAKeysAreRejected() {
    #expect(throws: Error.self) {
        try WebTransportPrivateKeyKind.rsa(sizeInBits: 1024).validate()
    }
    #expect(throws: Never.self) {
        try WebTransportPrivateKeyKind.rsa(sizeInBits: 2048).validate()
    }
}

@Test
func malformedPKCS12BundlesAreRejected() {
    let endpoint = WebTransportNetworkEndpoint(host: "0.0.0.0", port: 443)
    for bundle in [Data(), Data([0x30, 0x82, 0x00, 0x00]), Data(repeating: 0xab, count: 64)] {
        #expect(throws: Error.self) {
            _ = try ServerIdentityResolver.resolve(
                .pkcs12(data: bundle, passphrase: "wrong"),
                endpoint: endpoint, authority: "webtransport.test", localOnly: false
            )
        }
    }
}

// MARK: - PKCS#12 bundles Security.framework cannot build an identity from
//
// Regression coverage for issue #20. A bundle whose certificate carries explicit
// elliptic-curve parameters rather than a named curve makes `SecPKCS12Import`
// dereference a NULL `SecKeyRef` and raise `NSInvalidArgumentException`. Swift
// cannot catch an Objective-C exception, so before the exception boundary was
// added this terminated the test process rather than failing a test — which is
// why these cases need a real bundle rather than synthesised bytes.
//
// Both fixtures were produced by the macOS system `openssl` (LibreSSL 3.3.6);
// see Resources/README.md for the exact commands and checksums.

/// Loads a fixture copied into the test bundle by the package manifest.
///
/// SwiftPM flattens declared resources to the bundle root, so the lookup uses the
/// bare file name rather than the `Resources/` path from the manifest.
private func identityFixture(named name: String) throws -> Data {
    let url = try #require(
        Bundle.module.url(forResource: name, withExtension: "p12"),
        "missing fixture \(name).p12; is it declared in Package.swift resources?"
    )
    return try Data(contentsOf: url)
}

@Test
func pkcs12WithExplicitCurveParametersThrowsInsteadOfTerminating() throws {
    let bundle = try identityFixture(named: "libressl-explicit-curve-identity")

    // This pins the observed macOS 26 behaviour: the import raises rather than
    // returning a status, so the exception boundary is what produces the error. If
    // a future macOS instead imports the bundle successfully, this test is the
    // signal to revisit the error contract rather than a defect in the fix.
    //
    // If the exception boundary regresses, the process dies here and this test
    // never reports a failure — the suite aborts instead.
    let error = #expect(throws: WebTransportNetworkRuntimeError.self) {
        _ = try ServerIdentityResolver.resolve(
            .pkcs12(data: bundle, passphrase: "pw"),
            endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433),
            authority: "localhost",
            localOnly: false
        )
    }

    guard case .invalidTransport(let message) = try #require(error) else {
        Issue.record("expected .invalidTransport, got \(String(describing: error))")
        return
    }
    // The message has to name the cause and a way out, since the failure is
    // otherwise indistinguishable from a wrong passphrase.
    #expect(message.contains("could not be constructed"))
    #expect(message.contains("explicit elliptic-curve parameters"))
    #expect(message.contains("named curve"))
    // The exception name is useful and stable, so it is reported.
    #expect(message.contains("NSInvalidArgumentException"))
    // The exception reason is not, and the trust rules keep framework-supplied text
    // out of public errors. Pin that so a future change does not quietly splice it in.
    //
    // Caveat: this asserts the absence of one specific framework string, so it becomes
    // vacuous rather than failing if Apple rewords that reason. It cannot be made
    // stronger from here — the shim deliberately no longer captures the reason at all,
    // so there is nothing to compare against.
    #expect(
        !message.contains("SecKeyCopyExternalRepresentation called with NULL SecKeyRef"),
        "raw framework exception text leaked into the public error: \(message)"
    )
}

@Test
func pkcs12WithRSAIdentityStillResolvesAfterTheExceptionBoundary() throws {
    let bundle = try identityFixture(named: "libressl-rsa-identity")

    // The reporter's workaround, and the control that proves the boundary does
    // not reject valid bundles.
    let resolved = try ServerIdentityResolver.resolve(
        .pkcs12(data: bundle, passphrase: "pw"),
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433),
        authority: "localhost",
        localOnly: false
    )
    #expect(!resolved.leafCertificateDER.isEmpty)
}

@Test
func pkcs12WithWrongPassphraseReportsAnImportFailure() throws {
    let bundle = try identityFixture(named: "libressl-rsa-identity")

    // The ordinary failure path: no exception is raised, so the status returned by
    // SecPKCS12Import has to survive the shim unchanged and be reported as itself.
    let error = #expect(throws: WebTransportNetworkRuntimeError.self) {
        _ = try ServerIdentityResolver.resolve(
            .pkcs12(data: bundle, passphrase: "not-the-passphrase"),
            endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433),
            authority: "localhost",
            localOnly: false
        )
    }

    guard case .invalidTransport(let message) = try #require(error) else {
        Issue.record("expected .invalidTransport, got \(String(describing: error))")
        return
    }
    #expect(message.contains("PKCS#12 import failed"))
    #expect(message.contains("OSStatus"))
}

// MARK: - Injected key encoding diagnostics

@Test
func rejectedRSAKeyNamesTheEncodingAppleExpects() throws {
    // `privateKeyDER` invites DER, but SecKeyCreateWithData wants the representation
    // SecKeyCopyExternalRepresentation returns. A bare `OSStatus -50` does not say so,
    // which makes a wrong-but-plausible input hard to diagnose, so the error has to
    // name the expected form and the rejected ones.
    let material = try makeInjectableIdentityMaterial()

    let error = #expect(throws: (any Error).self) {
        _ = try ServerIdentityResolver.resolve(
            .certificateChain(
                chainDER: material.chainDER,
                privateKeyDER: Data(repeating: 0xa5, count: 1_218),
                keyKind: .rsa(sizeInBits: 2048)
            ),
            endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433),
            authority: "localhost",
            localOnly: false
        )
    }

    let message = String(describing: try #require(error))
    #expect(message.contains("SecKeyCopyExternalRepresentation"), "message was: \(message)")
    #expect(message.contains("PKCS#1"), "message was: \(message)")
}

@Test
func documentedPrivateKeyLengthsMatchWhatThePlatformProduces() throws {
    // The error message and the documentation both state exact EC private-key lengths,
    // and a caller is expected to check their blob against them. Pin every curve rather
    // than only P-256, because a wrong figure for the others would ship unnoticed.
    //
    // Measured on this platform: the private representation is the raw uncompressed
    // point followed by the private scalar, which is why it is larger than the point.
    let expected: [(kind: WebTransportPrivateKeyKind, bits: Int, bytes: Int)] = [
        (.ellipticCurveP256, 256, 97),
        (.ellipticCurveP384, 384, 145),
        (.ellipticCurveP521, 521, 199),
    ]

    for entry in expected {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: entry.kind.secAttrKeyType,
            kSecAttrKeySizeInBits: entry.bits,
            kSecAttrIsPermanent: false,
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, nil),
            let exported = SecKeyCopyExternalRepresentation(key, nil) as Data?
        else {
            Issue.record("could not generate a \(entry.bits)-bit key")
            continue
        }
        #expect(
            exported.count == entry.bytes,
            "\(entry.bits)-bit private export was \(exported.count) bytes, documented as \(entry.bytes)"
        )
    }
}

@Test
func rejectedP256KeyNamesTheExpectedByteLength() throws {
    let material = try makeInjectableIdentityMaterial()

    // 65 bytes is the uncompressed curve point, which is what a reader would guess and
    // is exactly what SecKeyCreateWithData rejects; the accepted form is the 97-byte
    // Apple raw private representation.
    let error = #expect(throws: (any Error).self) {
        _ = try ServerIdentityResolver.resolve(
            .certificateChain(
                chainDER: material.chainDER,
                privateKeyDER: Data(repeating: 0x5a, count: 65),
                keyKind: .ellipticCurveP256
            ),
            endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433),
            authority: "localhost",
            localOnly: false
        )
    }

    let message = String(describing: try #require(error))
    #expect(message.contains("97 bytes"), "message was: \(message)")
    #expect(message.contains("scalar"), "message was: \(message)")
}

@Test
func documentedConfigurationIsAccepted() throws {
    // Pins the guidance in the doc comments and the wiki: the bytes
    // SecKeyCopyExternalRepresentation returns for the private key are the bytes
    // SecKeyCreateWithData accepts, and an EC key in that form resolves. If this ever
    // fails, the documented remedy is wrong.
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecAttrIsPermanent: false,
    ]
    // The optionals are unwrapped with guards rather than `#require`: the macro
    // expansion does not carry an `unsafe` marker through to the call it wraps, so
    // the Security.framework calls are made outside it. Passing `nil` for the error
    // out-parameters means these calls perform no unsafe pointer operation.
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil),
        let publicKey = SecKeyCopyPublicKey(privateKey),
        let publicKeyPoint = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
        let privateKeyBytes = SecKeyCopyExternalRepresentation(privateKey, nil) as Data?
    else {
        Issue.record("could not generate and export a test identity")
        return
    }
    #expect(privateKeyBytes.count == 97, "expected the 97-byte raw EC private representation")

    let certificateDER = try SelfSignedCertificate.make(
        privateKey: privateKey,
        p256PublicKeyDER: publicKeyPoint,
        commonName: "documented.test",
        dnsNames: ["documented.test"],
        ipAddresses: []
    )

    let resolved = try ServerIdentityResolver.resolve(
        .certificateChain(
            chainDER: [certificateDER],
            privateKeyDER: privateKeyBytes,
            keyKind: .ellipticCurveP256
        ),
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433),
        authority: "documented.test",
        localOnly: false
    )
    #expect(!resolved.leafCertificateDER.isEmpty)
}

// MARK: - Listener wiring

@Test
func listenerRefusesDevelopmentCertificateOnRoutableBindAddress() {
    #expect(throws: Error.self) {
        _ = try WebTransportQUICServer(
            endpoint: WebTransportNetworkEndpoint(host: "0.0.0.0", port: 0),
            authority: "example.com",
            localOnly: false
        )
    }
}

@Test
func listenerReportsDevelopmentCertificateUsage() throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    defer { server.shutdown() }
    #expect(server.usesDevelopmentCertificate)
    #expect(server.certificateSHA256.count == 32)

    let material = try makeInjectableIdentityMaterial()
    let injected = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "webtransport.test",
        localOnly: false,
        identity: .certificateChain(
            chainDER: material.chainDER,
            privateKeyDER: material.privateKeyDER,
            keyKind: .ellipticCurveP256
        )
    )
    defer { injected.shutdown() }
    #expect(!injected.usesDevelopmentCertificate)
    #expect(injected.certificateSHA256 == Data(SHA256.hash(data: material.chainDER[0])))
}
