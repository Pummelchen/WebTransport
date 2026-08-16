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
