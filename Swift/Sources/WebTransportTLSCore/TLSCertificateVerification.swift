import Foundation
import Security
import WebTransportQUICCore

public enum TLSCertificateVerifyRole: Equatable, Sendable {
    case server
    case client

    var contextString: String {
        switch self {
        case .server:
            "TLS 1.3, server CertificateVerify"
        case .client:
            "TLS 1.3, client CertificateVerify"
        }
    }
}

public enum TLSCertificateVerifier {
    public static func signedContent(role: TLSCertificateVerifyRole, transcriptHash: Data) -> Data {
        var content = Data(repeating: 0x20, count: 64)
        content.append(contentsOf: role.contextString.utf8)
        content.append(0x00)
        content.append(transcriptHash)
        return content
    }

    public static func secKeyAlgorithm(for signatureScheme: UInt16) throws -> SecKeyAlgorithm {
        switch signatureScheme {
        case TLSSignatureScheme.rsaPSSRSAESHA256:
            return .rsaSignatureMessagePSSSHA256
        case TLSSignatureScheme.ecdsaSecp256r1SHA256:
            return .ecdsaSignatureMessageX962SHA256
        default:
            throw QUICCodecError.malformed("unsupported CertificateVerify signature scheme")
        }
    }

    public static func verify(
        _ certificateVerify: TLSCertificateVerify,
        role: TLSCertificateVerifyRole,
        transcriptHash: Data,
        publicKey: SecKey
    ) throws -> Bool {
        let algorithm = try secKeyAlgorithm(for: certificateVerify.algorithm)
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw QUICCodecError.malformed("public key does not support CertificateVerify algorithm")
        }

        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey,
            algorithm,
            signedContent(role: role, transcriptHash: transcriptHash) as CFData,
            certificateVerify.signature as CFData,
            &error
        )
        if result {
            return true
        }
        _ = error?.takeRetainedValue()
        return false
    }
}
