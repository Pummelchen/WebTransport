import CryptoKit
import Foundation
import Security
import WebTransportQUICCore

public struct TLSPromptFreeServerIdentity {
    public var certificateChainDER: [Data]
    public var privateKeyDER: Data
    public var privateKeyType: CFString
    public var privateKeySizeInBits: Int

    public init(
        certificateChainDER: [Data],
        privateKeyDER: Data,
        privateKeyType: CFString,
        privateKeySizeInBits: Int
    ) throws {
        guard !certificateChainDER.isEmpty else {
            throw QUICCodecError.malformed("server identity must include a certificate chain")
        }
        guard !privateKeyDER.isEmpty else {
            throw QUICCodecError.malformed("server identity private key DER must not be empty")
        }
        guard privateKeySizeInBits > 0 else {
            throw QUICCodecError.valueOutOfRange("server identity private key size must be positive")
        }

        self.certificateChainDER = certificateChainDER
        self.privateKeyDER = privateKeyDER
        self.privateKeyType = privateKeyType
        self.privateKeySizeInBits = privateKeySizeInBits
    }

    public func makeCertificateChain() throws -> [SecCertificate] {
        try certificateChainDER.enumerated().map { index, der in
            guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
                throw QUICCodecError.malformed("certificate \(index) is not valid DER")
            }
            return certificate
        }
    }

    public func makePrivateKey() throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: privateKeyType,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: privateKeySizeInBits,
            kSecAttrIsPermanent: false
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(privateKeyDER as CFData, attributes as CFDictionary, &error) else {
            throw QUICCodecError.malformed(
                error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateWithData rejected private key"
            )
        }
        return key
    }
}

public struct TLSPinnedCertificateTrustPolicy: Equatable, Sendable {
    public var allowedLeafCertificateSHA256Fingerprints: Set<Data>

    public init(allowedLeafCertificateSHA256Fingerprints: Set<Data>) throws {
        guard !allowedLeafCertificateSHA256Fingerprints.isEmpty else {
            throw QUICCodecError.malformed("trust policy must include at least one certificate fingerprint")
        }
        for fingerprint in allowedLeafCertificateSHA256Fingerprints {
            guard fingerprint.count == TLS13KeySchedule.sha256Length else {
                throw QUICCodecError.malformed("certificate SHA-256 fingerprint must be 32 bytes")
            }
        }
        self.allowedLeafCertificateSHA256Fingerprints = allowedLeafCertificateSHA256Fingerprints
    }

    public func evaluate(certificateChainDER: [Data]) throws {
        guard let leaf = certificateChainDER.first else {
            throw QUICCodecError.malformed("peer certificate chain is empty")
        }
        for (index, certificateDER) in certificateChainDER.enumerated() {
            guard SecCertificateCreateWithData(nil, certificateDER as CFData) != nil else {
                throw QUICCodecError.malformed("peer certificate \(index) is not valid DER")
            }
        }

        let fingerprint = Self.sha256Fingerprint(certificateDER: leaf)
        guard allowedLeafCertificateSHA256Fingerprints.contains(fingerprint) else {
            throw QUICCodecError.malformed("peer leaf certificate fingerprint is not pinned")
        }
    }

    public static func sha256Fingerprint(certificateDER: Data) -> Data {
        Data(SHA256.hash(data: certificateDER))
    }
}
