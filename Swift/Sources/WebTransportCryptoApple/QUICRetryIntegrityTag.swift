import CryptoKit
import Foundation
import WebTransportQUICCore

/// The Retry Integrity Tag of RFC 9001 section 5.8, for QUIC version 1.
///
/// A Retry packet carries no packet protection, so the only thing that makes it trustworthy is this tag: it is
/// an AEAD_AES_128_GCM tag computed with a key and nonce the RFC fixes for version 1, over the Retry
/// Pseudo-Packet of section 5.8 (the Original Destination Connection ID, its length, and the whole Retry packet
/// except the tag) with an empty associated data value. A client that does not check it accepts a forged Retry
/// from anyone who can guess the connection ID, which is what `WT-1` was.
///
/// The key and nonce are constants of the RFC, not secrets, and they are *not* derived from a connection: two
/// implementations that disagree about them produce tags that never match, so the repository's own vector —
/// RFC 9001 appendix A.4's packet and tag — is the check rather than a round trip through this code.
///
/// The seal is a one-shot with an empty plaintext: `AES.GCM` over no bytes yields exactly the 16-byte tag, and
/// verification goes through `AES.GCM.open`, so the comparison is the platform's constant-time one instead of
/// an equality test on the tag.
public enum QUICRetryIntegrityTag {
    /// RFC 9001 section 5.8: the version 1 key is
    /// `0xbe0c690b9f66575a1d766b54e368c84e`.
    public static let key = Data([
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    ])

    /// RFC 9001 section 5.8: the version 1 nonce is `0x461599d35d632bf2239825bb`.
    public static let nonce = Data([
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
        0x23, 0x98, 0x25, 0xbb,
    ])

    /// The tag RFC 9001 section 5.8 defines for `pseudoPacket`, which
    /// `QUICRetryPacket.integrityPseudoPacket(originalDestinationConnectionID:retryPacketWithoutIntegrityTag:)`
    /// builds.
    public static func compute(pseudoPacket: Data) throws -> Data {
        let sealedBox = try AES.GCM.seal(
            Data(),
            using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: pseudoPacket
        )
        return Data(sealedBox.tag)
    }

    /// Whether `integrityTag` is the tag of `pseudoPacket`. A wrong length is a failure rather than an error a
    /// caller could mistake for a packet that authenticated, and so is every authentication failure.
    public static func verify(pseudoPacket: Data, integrityTag: Data) -> Bool {
        guard integrityTag.count == 16 else { return false }
        do {
            _ = try AES.GCM.open(
                AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: Data(), tag: integrityTag),
                using: SymmetricKey(data: key),
                authenticating: pseudoPacket
            )
            return true
        } catch {
            return false
        }
    }
}
