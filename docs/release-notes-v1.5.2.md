# WebTransport 1.5.2

Both libraries, one tag, one artifact each: **WebTransport 1.5.2** ships the Swift package
and the portable C99 library built for Apple Silicon (arm64), with a `.sha256` beside each
archive. It carries one Swift fix: a `.pkcs12` server identity now resolves on a host that
has no unlocked keychain, which is what a headless server, a daemon and a CI job with no
login session have. The C99 library is unchanged and is rebuilt and republished at the new
number because the two always carry the same version.

These notes are the changelog for this release. Each change is under the library it belongs
to, and the work that is genuinely one item for both is under **Both**.

### Swift

Fixed:

- **A `.pkcs12` identity resolves with no unlocked keychain, and no longer files the caller's private key in their keychain** (WT-262). `SecPKCS12Import`'s documented macOS behaviour is to import the identity into the **default keychain** — the SDK says its "normal behavior ... is to import items into process memory on iOS, and into the default keychain on macOS" — and the call passed only `kSecImportExportPassphrase`. On a host with no unlocked keychain the bundle decoded and then failed with `OSStatus -26276`, an undocumented code the error text reported as "check the passphrase and bundle format": the wrong cause, which is what made the finding expensive. On a host with an unlocked keychain the same call silently filed a copy of the caller's private key in their login keychain — a side effect nothing in the API contract asked for, and the reason the package's two other identity sources, `.developmentSelfSigned` and `.certificateChain`, already create their keys with `kSecAttrIsPermanent: false`. The import now passes `kSecImportToMemoryOnly: true`, the SDK's own spelling of "in-process identity", which the header documents as importing into process memory and ignoring keychain options; it is available since macOS 15 against this package's macOS 26 floor, so it is unconditional. The resolved identity is unchanged in kind: `SecIdentityCopyPrivateKey` and `SecIdentityCopyCertificate` both succeed on it, its key signs, and a listener bound with it completes a real session — which the new tests assert rather than assume. The invariant is now stated on `WebTransportServerIdentity` and enforced rather than documented: **resolving any identity source is keychain-free and prompt-free**, and `Swift/check-pkcs12-keychain-free.sh`, wired into `swift-ci.yml`, gives the PKCS#12 suites a default keychain that exists and is **locked** — the only state in which the fix is distinguishable from the bug, since a runner's unlocked keychain passes either way. On the pre-fix tree that check fails with `-26276`, and it restores the runner's keychain on every exit path.
- **The import's failure text names its cause and its remedy.** One "check the passphrase and bundle format" sentence was wrong for every status but one. `errSecAuthFailed` now says the passphrase is wrong or the bundle failed its integrity check; `errSecDecode` names a malformed, truncated or legacy-RC2 container and says to re-export with `PBES2`/`PBKDF2`, `AES-CBC` and a SHA-256 MAC; and the keychain codes, including `-26276`, are reported as the defect they are rather than as advice about the passphrase.

Added:

- `Swift/check-pkcs12-keychain-free.sh` and its `swift-ci.yml` step, which make the keychain-free invariant a gate rather than a comment, plus two tests in `WebTransportNetworkRuntimeTests`: `pkcs12IdentityServesALoopbackSession`, which binds a listener with the fixture identity and completes a session, and `pkcs12ResolutionAddsNothingToTheKeychain`, which counts the keychain identities carrying the bundle's leaf before and after a resolution and requires the count not to move.

Checks: `swift test` under `-warnings-as-errors -strict-concurrency=complete
-require-explicit-sendable` (**400 tests, run with the login keychain locked** — the state
that failed before the fix, and the run needs no workaround now), the new
`./Swift/check-pkcs12-keychain-free.sh`, ASan over the whole suite, `swift format lint
--strict` over both manifests, `check-api-compatibility.sh`, `check-manifest-sync.sh`,
`check-target-imports.sh`, `check-version-sync.sh`, and the arm64 release build. The rest of
the Swift gates — DocC, both CLI conformance suites, the library smoke pair, the
20000-iteration parser-fuzz run and the thread sanitizer — run in CI on this commit.

### C99

No changes. The library is rebuilt and republished at 1.5.2 because the two libraries always
carry the same version, so a caller pairing them knows the pair is compatible. `WT_ABI_VERSION`
and the protocol draft are separate axes and do not move with the library version.

Checks: `C99/scripts/build-and-test.sh --all` — 97 CTest tests in Debug, Release and
ASan+UBSan.

### Both

Changed:

- **The version lockstep moves to 1.5.2.** `VERSION` is the single source and
  `./Swift/check-version-sync.sh --write` wrote the C99 header and `WebTransportVersion.swift`
  from it, so the C99 CMake configure and the Swift gate both refuse the mismatch.

## What is not in this release

- **0-RTT and session resumption** are not implemented, in either library.
- **The HTTP/2 capsule binding** is not implemented; this is WebTransport over HTTP/3.
- **Server push and connection migration** are out of scope for this implementation.
- The Swift package is macOS-only and needs macOS 26+, Xcode 27 and Swift 6.4; the shipped binaries are arm64 only and are not notarized.
- The Swift client still **cannot set the TLS server name (SNI)**; the certificate is checked against the configured `authority`, but name-based virtual hosting is not reachable by address.

## Checks that ran elsewhere, and what did not run

Not run on the release machine, and reported as not checked rather than assumed: the Wine
suite and the FreeBSD VM job run in CI, the two macOS and three Linux C99 legs and the MSVC
and Clang-CL Windows legs run in CI, `ThreadSanitizer` runs in its own CI job, and there is no
LeakSanitizer on Darwin. The VPS interop suites need the routable host and are not re-run for
a Swift-only identity fix; their recorded results stand on the source they were run against.

## Checksums

```
WebTransport-swift-1.5.2-macos-arm64.tar.gz
  SHA256: SHA256_PENDING
  Bytes:  ARCHIVE_BYTES_PENDING

WebTransport-c99-1.5.2-macos-arm64.tar.gz
  SHA256: C99_SHA256_PENDING
  Bytes:  C99_ARCHIVE_BYTES_PENDING
```
