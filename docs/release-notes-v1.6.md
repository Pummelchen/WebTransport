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

No user-visible changes.

One guard was added that is worth knowing about even though it changes no artifact: a repository
gate (`Swift/check-unsafe-flags.sh`, `AUD-0017`) now refuses a package configuration carrying
dependency `unsafeFlags`. The API-compatibility check consumed the package *by path*, so it could
not see this — SwiftPM rejects such a package when it is used as a dependency but builds it happily
in place — and the gate exists so the mistake is caught here rather than in a consumer's build.

The rest of the audit's Swift findings were about enforcement: The rest of the audit's Swift findings were about enforcement:
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
  `80f5b1c`, and backed by `C99/tests/unit/test_quic_packet.c`, which pins a Version Negotiation
  packet's answer and executes the two leading guards the defect sat behind (`AUD-0029`). Before,
  the version list parsed as a Token Length and a one-byte "token", and the function returned
  `WT_OK` — which let a crafted version-zero packet suppress the server's Retry, since the caller
  had no version to check.
- **`NEW_TOKEN` no longer stores unvalidated wire input in a public field** (`AUD-0022`). The frame
  wrote the wire's declared token length into a public field — one nothing in this build reads —
  before the token had been checked as taken and before its length was known to be sane. The impact
  was latent rather than observable: the field is public, so it is part of what a consumer may read,
  and it held a value from the network rather than a validated one. It is now written only after
  validation.
- **A QPACK decoder capacity this build cannot honour is refused, and changing one is no longer
  silent** (`AUD-0027`, superseded by `7417aec`). 1.5.2 accepted any capacity and, on a changed
  value, re-initialised the decoder table — discarding whatever the peer had already inserted.
  `wt_http3_endpoint_set_decoder_capacity` now returns `WT_ERR_STATE` for a second call with a
  different capacity, and is a no-op when the capacity is unchanged.
- **The C99 sanitizer configuration builds with gcc** (`AUD-0038`). `-fno-sanitize=function` is a
  clang-only flag, and passing it to gcc made the sanitizer configuration unbuildable — on the one
  leg that would have caught it, because CI excluded it. The flag is now applied only when the
  compiler is clang, and the sanitizer step runs on every matrix entry.

Added:

- **The QPACK dynamic-table receive half is implemented and reachable through the public API**
  (`WT-265`). `wt_http3_endpoint_set_decoder_capacity` now honours a non-zero capacity, the endpoint
  applies the peer's encoder-stream instructions (`wt_http3_endpoint_on_qpack_encoder_bytes`) and
  reports how much of a chunk it consumed, and it writes Insert Count Increment and Section
  Acknowledgment (`wt_http3_endpoint_write_qpack_decoder_acks`). Before this release the encoder
  stream could not be parsed at all, so any dynamic reference from a peer failed with a
  decompression error that blamed the peer. This is the feature `AUD-0027` pointed at, and it is
  library-level: the shipped C99 tools call neither new function, so their wire behaviour is
  unchanged. Backed by `C99/tests/unit/test_http3_endpoint_requests.c`
  (`test_the_dynamic_table_is_filled_and_acknowledged`, and the re-pointed
  `test_request_headers_are_decoded`).
- **This release moves `WT_ABI_VERSION` from 1 to 2.** The public `wt_http3_endpoint_t` gained a
  field (`uint64_t decoder_acked_insert_count`), so a consumer compiled against an earlier header
  must recompile, and `wt_abi_version()` returns 2. `WebTransportVersion.abi` is 2 as well: the two
  libraries' ABI versions are identical on a release, and `check-version-sync.sh` now fails if they
  differ. The library version and the ABI version are separate axes; this release moves both, the
  version because a release is a release and the ABI because a public layout changed. Backed by
  `C99/tests/unit/test_version.c` (`wt_abi_version() == WT_ABI_VERSION`) and the Swift gate.

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
