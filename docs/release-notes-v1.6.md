# WebTransport 1.6

Both libraries, one tag, one artifact each: **WebTransport 1.6** ships the Swift package and the
portable C99 library built for Apple Silicon (arm64), with a `.sha256` beside each archive.

This is the first release after a pre-production audit of both libraries, and the first under the
`MAJOR.MINOR` scheme: a release is `1.6`, never `1.6.0`, and a bug-fix release moves the minor
number. The audit's user-visible work landed in the C99 library — a QUIC parsing defect, an
unvalidated public field, two refusals that were missing — plus one C99 feature that moves the ABI.
The Swift library has no user-visible behaviour change; most of what the audit did there was
tooling, tests and decomposition, which is why its file count changed and its behaviour did not.

These notes are the changelog for this release. Each change is under the library it belongs to, and
the work that is genuinely one item for both is under **Both**.

### Swift

Changed, and visible to a consumer of the package rather than to its users:

- **The package refuses unsafe build flags** (`AUD-0017`). The API-compatibility check consumed the
  package *by path*, so it could not see a configuration that only breaks a consumer — a dependency
  declared with `unsafeFlags` is rejected by SwiftPM when the package is used as a dependency, but
  not when it is built in place. The package now refuses such a configuration itself, so the failure
  happens where the mistake is rather than in the consumer's build.

No user-visible behaviour change. The rest of the audit's Swift findings were about enforcement:
SwiftLint had no committed config and was not run (`AUD-0006`), its rules and the formatter rewrote
each other's output (`AUD-0013`, `AUD-0014`), one autofix did not compile (`AUD-0016`), and the
address-sanitizer job ran three tests rather than the suite (`AUD-0020`). The public API surface is
unchanged: the diff in `Swift/Sources/WebTransport/` is decomposition into extensions and file
splits, not signature changes.

Checks: `swift test` — **394 tests, 0 failures** — under `-warnings-as-errors
-strict-concurrency=complete -require-explicit-sendable`; `swift format lint --strict` over both
manifests; `swiftlint lint --strict`; `swift build` clean.

### C99

Fixed:

- **A Version Negotiation packet is no longer read as an Initial with a token** (`AUD-0023`).
  `wt_quic_initial_token` inspected the packet without first establishing that it was an Initial, so
  a Version Negotiation packet — which has no token and no version the reader can honour — was
  parsed as one and its bytes reported as a token. It also reported no version the caller could
  check, so a caller could not tell which version the peer had answered with. Backed by
  `C99/tests/unit/test_quic_packet.c`, which now pins every walker's answer for a Version
  Negotiation packet, and by `AUD-0029`, which executes the two leading guards the defect sat
  behind.
- **`NEW_TOKEN` no longer stores unvalidated wire input in a public field** (`AUD-0022`). The frame
  wrote the wire's declared token length into a public field — one nothing in this build reads —
  before the token had been checked as taken and before its length was known to be sane. The impact
  was latent rather than observable: the field is public, so it is part of what a consumer may read,
  and it held a value from the network rather than a validated one. It is now written only after
  validation.
- **A QPACK decoder capacity this build cannot honour is refused** (`AUD-0027`). The public API
  accepted a dynamic-table capacity that cannot work, because nothing in this build parses the QPACK
  encoder stream. The refusal is now at the API boundary rather than a silent later failure.
- **The C99 sanitizer configuration builds with gcc** (`AUD-0038`). `-fno-sanitize=function` is a
  clang-only flag, and passing it to gcc made the sanitizer configuration unbuildable — on the one
  leg that would have caught it, because CI excluded it. The flag is now applied only when the
  compiler is clang, and the sanitizer step runs on every matrix entry.

Added:

- **The QPACK dynamic table is wired into the C99 HTTP/3 endpoint** (`WT-265`). The encoder and
  decoder stream handling is reachable from the endpoint rather than only from the core.
  **This moves `WT_ABI_VERSION` from 1 to 2**, because it changes the public
  `C99/include/webtransport/http3/endpoint.h`: a caller compiled against 1.5.2 must recompile. The
  library version and the ABI version are separate axes, and this release moves both — the version
  because a release is a release, the ABI because a public layout changed. Backed by
  `C99/tests/unit/test_http3_endpoint.c`.

Checks: `C99/scripts/build-and-test.sh` — **105 CTest tests** in Debug, Release and ASan+UBSan — a
fresh scratch configure and build with **0 warnings** scanned from the log, and
`C99/scripts/check-format.sh` clean over all 343 C sources.

### Both

Changed:

- **The version lockstep moves to 1.6, and the scheme becomes `MAJOR.MINOR`.** `VERSION` is the
  single source and `./Swift/check-version-sync.sh --write` wrote the C99 header
  (`WT_VERSION_MAJOR 1`, `WT_VERSION_MINOR 6`, `WT_VERSION_PATCH 0`) and
  `WebTransportVersion.swift` (`"1.6"`) from it, so the Swift gate and the C99 CMake configure both
  refuse a mismatch. `wt_version_string()` prints `1.6` rather than `1.6.0`, so the string agrees
  with the tag and with the artifact names. `WT_VERSION_PATCH` is kept and is `0`; it is in the
  public header and removing it would stop existing consumers compiling. The two validators, the
  C99 renderer and the test's derived expectation all accept a two-component value and compare the
  mirror the way the string is printed.
- **The C99 public headers changed since 1.5.2** — 47 headers, from the two fixes above and the
  QPACK endpoint work. The ABI version in the C99 header is the thing to check against; it is 2.

Checks: `./Swift/check-version-sync.sh` (the three mirrors agree), the C99 CMake configure, and the
version test, which derives its expectation from the header rather than repeating a literal.

## What is not in this release

- **0-RTT and session resumption** are not implemented, in either library.
- **The HTTP/2 capsule binding** is not implemented; this is WebTransport over HTTP/3.
- **Server push and connection migration** are out of scope for this implementation.
- The Swift package is macOS-only and needs macOS 26+, Xcode 27 and Swift 6.4; the shipped binaries
  are arm64 only and are not notarized.
- The Swift client still **cannot set the TLS server name (SNI)**; the certificate is checked
  against the configured `authority`, but name-based virtual hosting is not reachable by address.

## Checks that ran elsewhere, and what did not run

Not run on the release machine, and reported as not checked rather than assumed: the Wine suite and
the FreeBSD VM job run in CI, the macOS and Linux C99 legs and the MSVC and Clang-CL Windows legs
run in CI, `ThreadSanitizer` runs in its own CI job, and there is no LeakSanitizer on Darwin. The
VPS interop suites need the routable host and were not re-run for this release.

## Checksums

```
WebTransport-swift-1.6-macos-arm64.tar.gz
  SHA256: SHA256_PENDING
  Bytes:  ARCHIVE_BYTES_PENDING

WebTransport-c99-1.6-macos-arm64.tar.gz
  SHA256: C99_SHA256_PENDING
  Bytes:  C99_ARCHIVE_BYTES_PENDING
```
