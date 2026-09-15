import Foundation
import Security
import Testing
import WebTransportTestSupport

/// F-swift-line-security-10: `parseKeyType` mapped the Ed25519 key-type name to
/// `kSecAttrKeyTypeECSECPrimeRandom`, so a caller selecting ed25519 built a P-256
/// `SecKey` request and got a confusing `OSStatus` instead of being told the key
/// type is unsupported — or, with a P-256 blob, a silently mislabelled identity.
/// An unsupported name must fall through to the same refusal as any other.
@Test
func phase11ParseKeyTypeDoesNotMisleadEd25519AsECPrime() throws {
    #expect(try Phase11IdentitySupport.parseKeyType("rsa") == kSecAttrKeyTypeRSA)
    #expect(try Phase11IdentitySupport.parseKeyType("RSA") == kSecAttrKeyTypeRSA)
    #expect(try Phase11IdentitySupport.parseKeyType("ec") == kSecAttrKeyTypeECSECPrimeRandom)
    #expect(try Phase11IdentitySupport.parseKeyType("p256") == kSecAttrKeyTypeECSECPrimeRandom)
    #expect(try Phase11IdentitySupport.parseKeyType(nil) == kSecAttrKeyTypeRSA)

    #expect(throws: Phase11IdentityError.invalidArgument("unsupported key type: ed25519")) {
        _ = try Phase11IdentitySupport.parseKeyType("ed25519")
    }
    #expect(throws: Phase11IdentityError.invalidArgument("unsupported key type: ed448")) {
        _ = try Phase11IdentitySupport.parseKeyType("ed448")
    }
}
