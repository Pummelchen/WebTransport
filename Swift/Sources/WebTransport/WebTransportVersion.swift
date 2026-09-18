/// Library identity for the Swift package.
///
/// The authoritative value is the repository-root `VERSION` file. This constant
/// is a MIRROR of it, as are the `WT_VERSION_*` macros in the C99 header
/// `C99/include/webtransport/version.h`; `Swift/check-version-sync.sh` fails if
/// any of the three disagrees, and the C99 CMake configure fails on the same
/// mismatch.
///
/// Why the two libraries share one number: they ship together and are meant to
/// interoperate, so a caller pairing this package with the C99 library has no
/// other way to know the pair is compatible. A build with no code change is
/// recompiled at the new number rather than left behind on the old one — the
/// version tracks the release, not the diff.
public enum WebTransportVersion {
    /// The library version, `MAJOR.MINOR.PATCH`. Mirrors `VERSION`.
    public static let library = "1.5.2"

    /// The ABI version this build exposes.
    ///
    /// Deliberately NOT locked to ``library``: it moves only when a public
    /// declaration's shape changes in a way that a caller compiled against an
    /// earlier release would get wrong, so a bug-fix release changes the version
    /// and not this. A caller checking this is checking the thing that can
    /// actually break. Mirrors `WT_ABI_VERSION` in the C99 header.
    public static let abi = 1

    /// The protocol draft this implementation targets, as a `User-Agent` or
    /// diagnostic string. Mirrors `wt_protocol_draft()` in the C99 library.
    public static let protocolDraft = "draft-ietf-webtrans-http3-16"
}
