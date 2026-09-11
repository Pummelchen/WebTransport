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

    /// Builds the private key from ``privateKeyDER``.
    ///
    /// - Important: ``privateKeyDER`` must be the representation `SecKeyCreateWithData`
    ///   accepts, which is what `SecKeyCopyExternalRepresentation` produces when it is
    ///   asked for the **private** key. That is not the same bytes as the public key
    ///   export, and it is not the DER that `openssl` writes. For EC it is Apple's raw
    ///   private form (`0x04`, X, Y, then the private scalar); for RSA it is the PKCS#1
    ///   `RSAPrivateKey` layout Apple exports. A key in the `openssl` forms is rejected.
    ///   The thrown message names the expected form, because the raw `OSStatus -50`
    ///   carries no diagnostic value on its own.
    public func makePrivateKey() throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: privateKeyType,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: privateKeySizeInBits,
            kSecAttrIsPermanent: false,
        ]
        var error: Unmanaged<CFError>?
        // SAFETY: Security.framework initializes the optional retained CFError
        // out-parameter before returning failure; its ownership is transferred
        // exactly once below.
        guard let key = unsafe SecKeyCreateWithData(privateKeyDER as CFData, attributes as CFDictionary, &error) else {
            let detail =
                unsafe error?.takeRetainedValue().localizedDescription
                ?? "SecKeyCreateWithData rejected the private key"
            throw QUICCodecError.malformed(
                """
                \(detail). Expected the private key in the representation \
                SecKeyCopyExternalRepresentation returns for that key, not the DER \
                that openssl writes. \(Self.expectedKeyFormDescription(for: privateKeyType, sizeInBits: privateKeySizeInBits)) \
                \(Self.rejectedKeyFormDescription(for: privateKeyType)) \
                Export the key from a SecKey that already works, or supply the \
                identity as a PKCS#12 bundle instead.
                """
            )
        }
        return key
    }

    /// Describes the key shape `SecKeyCreateWithData` expects, for the error message.
    ///
    /// The EC lengths are exact and were measured against
    /// `SecKeyCopyExternalRepresentation` for a private key of each curve. They are
    /// stated because the length is the one property a caller can check against their
    /// own blob without a parser, and because the private form is noticeably larger
    /// than the public point a reader might expect — 65 bytes for P-256, not 97.
    ///
    /// The RSA length is given as approximate: the PKCS#1 encoding omits leading zero
    /// bytes of the modulus and exponents, so it varies by a few bytes between keys
    /// (1,190 to 1,193 observed for 2,048-bit keys) and an exact figure would be wrong
    /// for most inputs.
    private static func expectedKeyFormDescription(
        for keyType: CFString,
        sizeInBits: Int
    ) -> String {
        if keyType == kSecAttrKeyTypeRSA {
            return """
                Expected Apple's PKCS#1 RSAPrivateKey for a \(sizeInBits)-bit key \
                (roughly 1.2 KB at 2,048 bits); the length varies by a few bytes between keys.
                """
        }
        let curve: String
        switch sizeInBits {
        case 256: curve = "P-256, 97 bytes (the 65-byte public point followed by the 32-byte scalar)"
        case 384: curve = "P-384, 145 bytes (the 97-byte public point followed by the 48-byte scalar)"
        case 521: curve = "P-521, 199 bytes (the 133-byte public point followed by the 66-byte scalar)"
        default: curve = "a supported NIST curve"
        }
        return "Expected Apple's raw EC private representation: \(curve)."
    }

    /// Names the encodings that are rejected, which depend on the key type.
    private static func rejectedKeyFormDescription(for keyType: CFString) -> String {
        if keyType == kSecAttrKeyTypeRSA {
            return "A PKCS#1 key whose layout differs from Apple's export, or a PKCS#8 (PRIVATE KEY) key, is rejected."
        }
        return "A SEC1 or PKCS#8 key, as written by openssl, is rejected; Apple's form is not the same encoding."
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
