import CryptoKit
import Foundation
import Network
import Security
import WebTransportQUICCore
import WebTransportTLSCore

/// Private-key kind for an injected server identity supplied as raw DER.
public enum WebTransportPrivateKeyKind: Equatable, Sendable {
    case ellipticCurveP256
    case ellipticCurveP384
    case ellipticCurveP521
    case rsa(sizeInBits: Int)

    var secAttrKeyType: CFString {
        switch self {
        case .ellipticCurveP256, .ellipticCurveP384, .ellipticCurveP521:
            return kSecAttrKeyTypeECSECPrimeRandom
        case .rsa:
            return kSecAttrKeyTypeRSA
        }
    }

    var sizeInBits: Int {
        switch self {
        case .ellipticCurveP256:
            return 256
        case .ellipticCurveP384:
            return 384
        case .ellipticCurveP521:
            return 521
        case .rsa(let sizeInBits):
            return sizeInBits
        }
    }

    func validate() throws {
        if case .rsa(let sizeInBits) = self {
            guard sizeInBits >= 2048 else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    "RSA server keys smaller than 2048 bits are not accepted"
                )
            }
        }
    }
}

/// Source of the TLS identity a WebTransport server presents to peers.
///
/// Production deployments must supply a real, CA-issued identity through
/// ``pkcs12(data:passphrase:)`` or ``certificateChain(chainDER:privateKeyDER:keyKind:)``.
/// ``developmentSelfSigned`` is a development affordance and is refused on any
/// non-loopback bind address.
public enum WebTransportServerIdentity: Equatable, Sendable {
    /// Ephemeral self-signed identity generated in memory. Loopback binds only.
    ///
    /// The certificate is regenerated on every server construction, so its
    /// SHA-256 fingerprint changes across restarts. It is unusable for any
    /// deployment that requires a stable pin or a publicly verifiable chain.
    case developmentSelfSigned

    /// PKCS#12 bundle containing the leaf certificate, its chain, and the private key.
    case pkcs12(data: Data, passphrase: String)

    /// Explicit DER certificate chain (leaf first) with a matching private key.
    case certificateChain(chainDER: [Data], privateKeyDER: Data, keyKind: WebTransportPrivateKeyKind)

    var isDevelopmentSelfSigned: Bool {
        self == .developmentSelfSigned
    }
}

/// A resolved TLS identity ready to be handed to Network.framework.
struct ResolvedServerIdentity {
    var networkIdentity: sec_identity_t
    var leafCertificateDER: Data
    /// Expiry of the leaf certificate, when it could be read.
    ///
    /// Surfaced because Network.framework fixes the identity in the listener's
    /// parameters at construction, so an expiring certificate cannot be swapped
    /// in place — an operator has to schedule a rebind, and needs the deadline
    /// to do it before peers start failing validation.
    var notAfter: Date?

    var certificateSHA256: Data {
        Data(SHA256.hash(data: leafCertificateDER))
    }

    /// Reads the leaf certificate's `notAfter`.
    ///
    /// Returns nil rather than throwing: a certificate whose expiry cannot be
    /// read is still perfectly usable, and refusing to serve over a missing
    /// convenience value would be worse than serving without it.
    static func expiry(of certificate: SecCertificate) -> Date? {
        guard let values = SecCertificateCopyValues(certificate, [kSecOIDX509V1ValidityNotAfter] as CFArray, nil)
            as? [CFString: Any],
            let entry = values[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any],
            let raw = entry[kSecPropertyKeyValue] as? NSNumber else {
            return nil
        }
        // Security reports this as seconds since the Apple absolute reference date.
        return Date(timeIntervalSinceReferenceDate: raw.doubleValue)
    }
}

enum ServerIdentityResolver {
    /// Resolves an identity source for a specific bind endpoint.
    ///
    /// Enforces the loopback restriction on ``WebTransportServerIdentity/developmentSelfSigned``:
    /// a self-signed development certificate cannot be validated by any peer for
    /// a routable name, so binding one to a non-loopback address would produce a
    /// server that appears to work locally and fails for every real client.
    static func resolve(
        _ identity: WebTransportServerIdentity,
        endpoint: WebTransportNetworkEndpoint,
        authority: String,
        localOnly: Bool
    ) throws -> ResolvedServerIdentity {
        switch identity {
        case .developmentSelfSigned:
            guard localOnly || LoopbackHost.isLoopback(endpoint.host) else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    """
                    refusing to serve a self-signed development certificate on non-loopback \
                    address "\(endpoint.host)". Supply a CA-issued identity via \
                    WebTransportServerIdentity.pkcs12 or .certificateChain, or bind to loopback.
                    """
                )
            }
            return try makeDevelopmentSelfSigned(endpoint: endpoint, authority: authority)

        case .pkcs12(let data, let passphrase):
            return try makeFromPKCS12(data: data, passphrase: passphrase)

        case .certificateChain(let chainDER, let privateKeyDER, let keyKind):
            return try makeFromCertificateChain(
                chainDER: chainDER,
                privateKeyDER: privateKeyDER,
                keyKind: keyKind
            )
        }
    }

    // MARK: - PKCS#12

    private static func makeFromPKCS12(data: Data, passphrase: String) throws -> ResolvedServerIdentity {
        guard !data.isEmpty else {
            throw WebTransportNetworkRuntimeError.invalidTransport("PKCS#12 bundle is empty")
        }

        let options: [CFString: Any] = [kSecImportExportPassphrase: passphrase]
        var rawItems: CFArray?
        // SAFETY: Security.framework writes an optional retained CFArray to the
        // out-parameter and leaves it nil on failure; ownership transfers once.
        let status = unsafe SecPKCS12Import(data as CFData, options as CFDictionary, &rawItems)
        guard status == errSecSuccess else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "PKCS#12 import failed (OSStatus \(status)); check the passphrase and bundle format"
            )
        }
        guard let items = rawItems as? [[CFString: Any]], let first = items.first else {
            throw WebTransportNetworkRuntimeError.invalidTransport("PKCS#12 bundle contained no items")
        }
        guard let identity = first[kSecImportItemIdentity] as! SecIdentity? else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "PKCS#12 bundle contained no identity (certificate plus private key)"
            )
        }

        let chain = (first[kSecImportItemCertChain] as? [SecCertificate]) ?? []
        return try finish(identity: identity, chain: chain)
    }

    // MARK: - Explicit DER chain

    private static func makeFromCertificateChain(
        chainDER: [Data],
        privateKeyDER: Data,
        keyKind: WebTransportPrivateKeyKind
    ) throws -> ResolvedServerIdentity {
        try keyKind.validate()

        let promptFree = try TLSPromptFreeServerIdentity(
            certificateChainDER: chainDER,
            privateKeyDER: privateKeyDER,
            privateKeyType: keyKind.secAttrKeyType,
            privateKeySizeInBits: keyKind.sizeInBits
        )
        let chain = try promptFree.makeCertificateChain()
        let privateKey = try promptFree.makePrivateKey()

        guard let leaf = chain.first else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server certificate chain is empty")
        }
        guard let identity = SecIdentityCreate(nil, leaf, privateKey) else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "server identity creation failed; the private key does not match the leaf certificate"
            )
        }
        return try finish(identity: identity, chain: chain)
    }

    // MARK: - Development self-signed

    private static func makeDevelopmentSelfSigned(
        endpoint: WebTransportNetworkEndpoint,
        authority: String
    ) throws -> ResolvedServerIdentity {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrIsPermanent: false
        ]

        var privateKeyError: Unmanaged<CFError>?
        // SAFETY: Security.framework initializes the optional retained CFError
        // out-parameter; failure transfers that ownership exactly once below.
        guard let privateKey = unsafe SecKeyCreateRandomKey(attributes as CFDictionary, &privateKeyError) else {
            let detail = unsafe privateKeyError?.takeRetainedValue().localizedDescription
                ?? "unknown Security.framework error"
            throw WebTransportNetworkRuntimeError.invalidTransport("server key generation failed: \(detail)")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server public key extraction failed")
        }
        var publicKeyError: Unmanaged<CFError>?
        // SAFETY: As above, the retained error is consumed only on failure.
        guard let publicKeyData = unsafe SecKeyCopyExternalRepresentation(publicKey, &publicKeyError) as Data? else {
            let detail = unsafe publicKeyError?.takeRetainedValue().localizedDescription
                ?? "unknown Security.framework error"
            throw WebTransportNetworkRuntimeError.invalidTransport("server public key export failed: \(detail)")
        }

        let subjectNames = SubjectNames.forDevelopment(endpoint: endpoint, authority: authority)
        let certificateDER = try SelfSignedCertificate.make(
            privateKey: privateKey,
            p256PublicKeyDER: publicKeyData,
            commonName: subjectNames.commonName,
            dnsNames: subjectNames.dnsNames,
            ipAddresses: subjectNames.ipAddresses
        )
        guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server certificate generation produced invalid DER")
        }
        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server identity creation failed")
        }
        return try finish(identity: identity, chain: [certificate])
    }

    // MARK: - Shared tail

    private static func finish(identity: SecIdentity, chain: [SecCertificate]) throws -> ResolvedServerIdentity {
        var leafCertificate: SecCertificate?
        // SAFETY: SecIdentityCopyCertificate writes an optional retained
        // certificate to the out-parameter; ownership transfers exactly once.
        let status = unsafe SecIdentityCopyCertificate(identity, &leafCertificate)
        guard status == errSecSuccess, let leaf = leafCertificate else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "could not read the leaf certificate from the server identity (OSStatus \(status))"
            )
        }
        let leafDER = SecCertificateCopyData(leaf) as Data
        guard !leafDER.isEmpty else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server leaf certificate encoded to zero bytes")
        }

        // Network.framework wants the full chain; fall back to the leaf alone.
        let presentedChain = chain.isEmpty ? [leaf] : chain
        guard let networkIdentity = sec_identity_create_with_certificates(identity, presentedChain as CFArray) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server QUIC identity conversion failed")
        }
        return ResolvedServerIdentity(
            networkIdentity: networkIdentity,
            leafCertificateDER: leafDER,
            notAfter: ResolvedServerIdentity.expiry(of: leaf)
        )
    }
}

// MARK: - Host classification

enum LoopbackHost {
    static func isLoopback(_ host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        if normalized == "localhost" || normalized == "::1" || normalized == "0:0:0:0:0:0:0:1" {
            return true
        }
        // Any 127.0.0.0/8 address is loopback.
        if let octets = IPv4.parse(normalized) {
            return octets[0] == 127
        }
        return false
    }
}

enum IPv4 {
    /// Parses a dotted-quad IPv4 literal. Returns nil for anything else.
    static func parse(_ value: String) -> [UInt8]? {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            return nil
        }
        var octets: [UInt8] = []
        octets.reserveCapacity(4)
        for part in parts {
            // Reject leading zeros and non-digits so "127.0.0.01" is not silently accepted.
            guard !part.isEmpty,
                  part.allSatisfy(\.isNumber),
                  part.count == 1 || part.first != "0",
                  let octet = UInt8(part) else {
                return nil
            }
            octets.append(octet)
        }
        return octets
    }
}

private struct SubjectNames {
    var commonName: String
    var dnsNames: [String]
    var ipAddresses: [[UInt8]]

    /// Names for the development certificate.
    ///
    /// Derived from the bind endpoint and the configured authority rather than
    /// hardcoded, so a loopback alias configured by the caller still validates.
    /// Only IPv4 literals and the `::1` loopback are encoded as IP SANs; any
    /// other host is treated as a DNS name. Deployments needing richer SAN sets
    /// supply their own certificate.
    static func forDevelopment(endpoint: WebTransportNetworkEndpoint, authority: String) -> SubjectNames {
        var dnsNames: [String] = ["localhost"]
        var ipAddresses: [[UInt8]] = [[127, 0, 0, 1], loopbackIPv6]

        for candidate in [endpoint.host, authorityHost(authority)] {
            let host = candidate.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
            guard !host.isEmpty else {
                continue
            }
            if let octets = IPv4.parse(host) {
                if !ipAddresses.contains(octets) {
                    ipAddresses.append(octets)
                }
            } else if host == "::1" {
                continue
            } else if !dnsNames.contains(host) {
                dnsNames.append(host)
            }
        }

        return SubjectNames(
            commonName: dnsNames.first ?? "localhost",
            dnsNames: dnsNames,
            ipAddresses: ipAddresses
        )
    }

    private static let loopbackIPv6: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

    /// Strips any `:port` suffix from an `:authority` value.
    private static func authorityHost(_ authority: String) -> String {
        if authority.hasPrefix("["), let close = authority.firstIndex(of: "]") {
            return String(authority[authority.index(after: authority.startIndex)..<close])
        }
        let parts = authority.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count == 2 ? String(parts[0]) : authority
    }
}

// MARK: - Self-signed certificate generation

enum SelfSignedCertificate {
    static func make(
        privateKey: SecKey,
        p256PublicKeyDER: Data,
        commonName: String,
        dnsNames: [String],
        ipAddresses: [[UInt8]]
    ) throws -> Data {
        let signatureAlgorithm = DER.sequence([
            try DER.objectIdentifier([1, 2, 840, 10045, 4, 3, 2])
        ])
        let ecPublicKeyAlgorithm = DER.sequence([
            try DER.objectIdentifier([1, 2, 840, 10045, 2, 1]),
            try DER.objectIdentifier([1, 2, 840, 10045, 3, 1, 7])
        ])
        let name = DER.sequence([
            DER.set([
                DER.sequence([
                    try DER.objectIdentifier([2, 5, 4, 3]),
                    DER.utf8String(commonName)
                ])
            ])
        ])
        let validity = DER.sequence([
            DER.utcTime(Date(timeIntervalSinceNow: -60)),
            DER.utcTime(Date(timeIntervalSinceNow: 86_400))
        ])
        let subjectPublicKeyInfo = DER.sequence([
            ecPublicKeyAlgorithm,
            DER.bitString(p256PublicKeyDER)
        ])

        var generalNames: [Data] = dnsNames.map { DER.contextSpecificPrimitive(2, Data($0.utf8)) }
        generalNames.append(contentsOf: ipAddresses.map { DER.contextSpecificPrimitive(7, Data($0)) })

        let extensions = DER.explicit(3, DER.sequence([
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 19]),
                DER.boolean(true),
                DER.octetString(DER.sequence([DER.boolean(false)]))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 15]),
                DER.boolean(true),
                DER.octetString(DER.bitString(Data([0x80]), unusedBits: 7))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 37]),
                DER.octetString(DER.sequence([
                    try DER.objectIdentifier([1, 3, 6, 1, 5, 5, 7, 3, 1])
                ]))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 17]),
                DER.octetString(DER.sequence(generalNames))
            ])
        ]))

        let tbsCertificate = DER.sequence([
            DER.explicit(0, DER.integer(Data([0x02]))),
            DER.integer(try randomSerial()),
            signatureAlgorithm,
            name,
            validity,
            name,
            subjectPublicKeyInfo,
            extensions
        ])

        var signError: Unmanaged<CFError>?
        // SAFETY: Security.framework initializes the optional retained CFError
        // out-parameter; failure transfers that ownership exactly once below.
        guard let signature = unsafe SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            tbsCertificate as CFData,
            &signError
        ) as Data? else {
            let detail = unsafe signError?.takeRetainedValue().localizedDescription
                ?? "unknown Security.framework error"
            throw WebTransportNetworkRuntimeError.invalidTransport("server certificate signing failed: \(detail)")
        }

        return DER.sequence([
            tbsCertificate,
            signatureAlgorithm,
            DER.bitString(signature)
        ])
    }

    /// A CSPRNG failure is fatal to certificate generation.
    ///
    /// Degrading to a weaker source would silently produce a certificate whose
    /// serial number is predictable, so this throws instead.
    private static func randomSerial() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        // SAFETY: `bytes` owns exactly the writable byte count supplied to
        // SecRandomCopyBytes and remains alive for the synchronous call.
        let status = unsafe SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "secure random generation failed (OSStatus \(status)); refusing to emit a certificate "
                + "with a predictable serial number"
            )
        }
        // Clear the high bit so the DER INTEGER stays positive without padding.
        bytes[0] &= 0x7f
        if bytes.allSatisfy({ $0 == 0 }) {
            bytes[0] = 1
        }
        return Data(bytes)
    }
}

// MARK: - Minimal DER writer

enum DER {
    static func sequence(_ parts: [Data]) -> Data {
        tagged(0x30, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func set(_ parts: [Data]) -> Data {
        tagged(0x31, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func explicit(_ tag: UInt8, _ content: Data) -> Data {
        tagged(0xa0 + tag, content)
    }

    static func contextSpecificPrimitive(_ tag: UInt8, _ value: Data) -> Data {
        tagged(0x80 + tag, value)
    }

    static func integer(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.count > 1 && bytes[0] == 0 && bytes[1] < 0x80 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first >= 0x80 {
            bytes.insert(0, at: 0)
        }
        return tagged(0x02, Data(bytes))
    }

    static func boolean(_ value: Bool) -> Data {
        tagged(0x01, Data([value ? 0xff : 0x00]))
    }

    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        tagged(0x03, Data([unusedBits]) + value)
    }

    static func octetString(_ value: Data) -> Data {
        tagged(0x04, value)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
    }

    static func objectIdentifier(_ components: [UInt64]) throws -> Data {
        guard components.count >= 2 else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let firstTwo = components[0] * 40 + components[1]
        var bytes = [UInt8(firstTwo)]
        for component in components.dropFirst(2) {
            var section = [UInt8(component & 0x7f)]
            var remaining = component >> 7
            while remaining > 0 {
                section.insert(UInt8(remaining & 0x7f) | 0x80, at: 0)
                remaining >>= 7
            }
            bytes.append(contentsOf: section)
        }
        return tagged(0x06, Data(bytes))
    }

    static func utf8String(_ value: String) -> Data {
        tagged(0x0c, Data(value.utf8))
    }

    static func utcTime(_ value: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tagged(0x17, Data(formatter.string(from: value).utf8))
    }

    fileprivate static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + encodeLength(content.count) + content
    }

    private static func encodeLength(_ value: Int) -> Data {
        if value < 128 {
            return Data([UInt8(value)])
        }
        var remaining = value
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
