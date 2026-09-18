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
    /// The library version, `MAJOR.MINOR` -- releases carry no third component. Mirrors
    /// `VERSION`.
    public static let library = "1.6"

    /// The ABI version this build exposes.
    ///
    /// Deliberately NOT locked to ``library``: it moves only when a public
    /// declaration's shape changes in a way that a caller compiled against an
    /// earlier release would get wrong, so a bug-fix release changes the version
    /// and not this. A caller checking this is checking the thing that can
    /// actually break.
    ///
    /// It IS locked to the C99 library's `WT_ABI_VERSION`, and must equal it on a
    /// release: a caller pairing the two libraries checks one ABI number, so a
    /// disagreement is the same class of defect as a library-version mismatch.
    /// `Swift/check-version-sync.sh` fails when the two differ.
    public static let abi = 2

    /// The protocol draft this implementation targets, as a `User-Agent` or
    /// diagnostic string. Mirrors `wt_protocol_draft()` in the C99 library.
    public static let protocolDraft = "draft-ietf-webtrans-http3-16"
}
