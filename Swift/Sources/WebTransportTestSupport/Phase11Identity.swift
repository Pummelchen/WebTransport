import Foundation
import CryptoKit
import Security
import WebTransportTLSCore

public enum Phase11IdentityError: Error, CustomStringConvertible {
    case invalidArgument(String)

    public var description: String {
        switch self {
        case .invalidArgument(let message):
            return "Invalid identity argument: \(message)"
        }
    }
}

public enum Phase11IdentitySupport {
    public struct Configuration {
        public var certificatePath: String?
        public var privateKeyPath: String?
        public var privateKeyTypeName: String?
        public var privateKeySizeInBits: Int?

        public init(
            certificatePath: String? = nil,
            privateKeyPath: String? = nil,
            privateKeyTypeName: String? = nil,
            privateKeySizeInBits: Int? = nil
        ) {
            self.certificatePath = certificatePath
            self.privateKeyPath = privateKeyPath
            self.privateKeyTypeName = privateKeyTypeName
            self.privateKeySizeInBits = privateKeySizeInBits
        }

        public var isComplete: Bool {
            certificatePath != nil && privateKeyPath != nil
        }
    }

    public struct LoadedIdentity {
        public let identity: TLSPromptFreeServerIdentity
        public let certificateSHA256: Data

        public init(configuration: Configuration) throws {
            guard let certPath = configuration.certificatePath else {
                throw Phase11IdentityError.invalidArgument("missing certificate path")
            }
            guard let keyPath = configuration.privateKeyPath else {
                throw Phase11IdentityError.invalidArgument("missing private key path")
            }
            let keySize = configuration.privateKeySizeInBits ?? 2048
            guard keySize > 0 else {
                throw Phase11IdentityError.invalidArgument("private key size must be positive")
            }

            let certData = try Data(contentsOf: URL(fileURLWithPath: certPath))
            let keyData = try Data(contentsOf: URL(fileURLWithPath: keyPath))
            let keyType = try Phase11IdentitySupport.parseKeyType(configuration.privateKeyTypeName)

            let identity = try TLSPromptFreeServerIdentity(
                certificateChainDER: [certData],
                privateKeyDER: keyData,
                privateKeyType: keyType,
                privateKeySizeInBits: keySize
            )

            self.identity = identity
            guard let certificate = try identity.makeCertificateChain().first else {
                throw Phase11IdentityError.invalidArgument("certificate chain is empty")
            }

            let certificateDER = SecCertificateCopyData(certificate) as Data
            self.certificateSHA256 = Data(SHA256.hash(data: certificateDER))
        }

        public var certificateFingerprintHex: String {
            certificateSHA256.map { String(format: "%02x", $0) }.joined()
        }

    }

    public static func parseKeyType(_ raw: String?) throws -> CFString {
        let value = raw?.lowercased().trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !value.isEmpty else {
            return kSecAttrKeyTypeRSA
        }

        switch value {
        case "rsa":
            return kSecAttrKeyTypeRSA
        case "ec", "ecsecprimerandom", "prime", "p256":
            return kSecAttrKeyTypeECSECPrimeRandom
        case "ed25519":
            return kSecAttrKeyTypeECSECPrimeRandom
        default:
            throw Phase11IdentityError.invalidArgument("unsupported key type: \(value)")
        }
    }
}
