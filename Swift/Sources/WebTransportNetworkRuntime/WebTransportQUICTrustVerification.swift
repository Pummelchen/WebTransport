import Foundation
import Security

/// The host part of an authority, which is the name a server's certificate has to be valid for.
///
/// An authority is `host` or `host:port` (RFC 3986 section 3.2), and an IPv6 literal carries its colons inside
/// square brackets, so the port is what follows the last colon only when the host is not bracketed, and the
/// brackets themselves are not part of the name.
internal enum InteroperableQUICAuthority {
    static func host(of authority: String) -> String {
        let trimmed = authority.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("[") {
            guard let close = trimmed.firstIndex(of: "]") else {
                return String(trimmed.dropFirst())
            }
            return String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
        }
        guard let colon = trimmed.lastIndex(of: ":") else {
            return trimmed
        }
        // Several colons in front of the last one mean this is a bare IPv6 literal rather than `host:port`: there
        // is no port to strip, and stripping would leave a fragment of the address.
        if trimmed[trimmed.startIndex..<colon].contains(":") {
            return trimmed
        }
        return String(trimmed[trimmed.startIndex..<colon])
    }
}

/// Verifying a server's certificate against the name the caller asked for.
internal enum InteroperableQUICCertificateVerification {
    /// Evaluates `trust` with the platform's SSL policy for `name`: the chain must end at a trusted anchor **and**
    /// the certificate must be valid for that name.
    ///
    /// This is the framework's own check with one input changed. It exists because `NetworkConnection` validates
    /// against the address it was opened with and the new API exposes no server-name override, so a caller reaching
    /// a server **by address** for a name its certificate carries would otherwise fail the handshake with a TLS
    /// `bad_certificate` alert (WT-261). The trust anchors are deliberately NOT touched — `SecTrustEvaluateWithError`
    /// uses the platform's own trust store, so the decision about *who* is trusted stays where it belongs; the only
    /// thing this decides is *which name* the certificate must prove.
    static func isValid(_ trust: sec_trust_t, forName name: String) -> Bool {
        // SAFETY: `sec_trust_copy_ref` follows the Copy rule and returns a reference this call owns, and
        // `takeRetainedValue` consumes exactly that one reference. The `sec_trust_t` handed in belongs to the
        // caller and is not touched.
        let secTrust = unsafe sec_trust_copy_ref(trust).takeRetainedValue()
        let policy = SecPolicyCreateSSL(true, name as CFString)
        guard SecTrustSetPolicies(secTrust, [policy] as CFArray) == errSecSuccess else {
            return false
        }
        var error: CFError?
        // SAFETY: `SecTrustEvaluateWithError` initializes the optional retained `CFError` out-parameter before
        // returning, and a non-nil one transfers that ownership here; leaving it unmanaged leaks it rather than
        // releasing a reference we do not own.
        return unsafe SecTrustEvaluateWithError(secTrust, &error)
    }
}
