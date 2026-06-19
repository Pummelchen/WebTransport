import Foundation
import Security
import Testing
import WebTransportQUICCore
@testable import WebTransportTLSCore

@Test
func tlsTrustPolicyAcceptsPinnedLeafAndRejectsWrongFingerprint() throws {
    let certificateDER = try TLSInteropSelfSignedCertificate.makeRSACertificate()
    let policy = try TLSPinnedCertificateTrustPolicy(
        allowedLeafCertificateSHA256Fingerprints: Set([TLSPinnedCertificateTrustPolicy.sha256Fingerprint(certificateDER: certificateDER)])
    )
    try policy.evaluate(certificateChainDER: [certificateDER])

    let rejectionPolicy = try TLSPinnedCertificateTrustPolicy(
        allowedLeafCertificateSHA256Fingerprints: Set([Data(repeating: 0x00, count: TLS13KeySchedule.sha256Length)])
    )
    #expect(throws: Error.self) {
        try rejectionPolicy.evaluate(certificateChainDER: [certificateDER])
    }

    #expect(throws: Error.self) {
        try policy.evaluate(certificateChainDER: [Data([0x00, 0x01])])
    }
}

@Test
func tlsIdentityRejectsMalformedKeyMaterialWithoutPrompt() {
    let identity = try! TLSPromptFreeServerIdentity(
        certificateChainDER: [Data([0x30, 0x01])],
        privateKeyDER: Data([0x00, 0x01, 0x02]),
        privateKeyType: kSecAttrKeyTypeRSA,
        privateKeySizeInBits: 2_048
    )
    #expect(throws: Error.self) {
        _ = try identity.makeCertificateChain()
    }
    #expect(throws: Error.self) {
        _ = try identity.makePrivateKey()
    }
}

private enum TLSInteropSelfSignedCertificate {
    static func makeRSACertificate() throws -> Data {
        guard let certificateDER = Data(
            base64Encoded: SelfSignedCertificateDER.derBase64,
            options: .ignoreUnknownCharacters
        ) else {
            throw QUICCodecError.malformed("invalid self-signed certificate fixture")
        }
        return certificateDER
    }
}

private enum SelfSignedCertificateDER {
    static let derBase64 = """
    MIIDHzCCAgegAwIBAgIUPByc28F3tfpRpYaQZdEPtYmJKeMwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYxOTAyMDA1NloXDTI2MDYyMDAyMDA1NlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4IUwlpWT2KgW7ILsD2qubjRBMGrGV/tlRCQVvTxOiv0yN3MTBvoMZgFNtLSscRXKNk6OkUX5Jaiq11hanLOBEZ/beiCu5EjzP/H09CdNgqSRStPoF4frIsFfAMjOyyE2LRuj8+Yjw1r2OueHESe0s1y/LHkF8/HarQyXOyKTcmceGsKArACP4ceT6aveM46Rs7aBqma/+lUnnfHatAMTr9xMjc/Mgg0XJEEFBWgYf2v1WJnGwUxKJ53wRdAB95aACfU2mHS8gB/dzOFfVX0P4HD8DDn+R6JmXgY0Lb9uxalje6/ARrCudJoXFvqgs+mNLy4fViK+PrTMhcj4wTX5rwIDAQABo2kwZzAdBgNVHQ4EFgQUEEIHs0CmftlkzVGFvGnkdU51SvwwHwYDVR0jBBgwFoAUEEIHs0CmftlkzVGFvGnkdU51SvwwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAERPDeSqneOTjtQVaI71mg8z6KceW8Sre1p5b8ceyyvSjnHW+G6le3VY/1iU9lIhbGvguqkTd1byXuYNfrGJrVN6kSw8aOpq4TQNQ+PJz0nkxRquVwQ/EnqJ+3xd3O571V72uUkRLzDIYenWJvjX9ML4Qv9SgxD4bTxqZ033Rx4YC+xXhu/KgsvvxgsJKZyDHKCnFJqTwJMeMGA6+9ZT5e5nlPnSoVOwK6pAjHOVrVAyN4zu7c0BGXVwVIU4mfaujyUvPMfQzpk/pUTzVzXNv4RGMZffbqogX9d9COeZ4CdZGbixz3OW7i1H3x2NBpeYvOLYHQ089jIKRk7MauGEEY4=
    """
}
