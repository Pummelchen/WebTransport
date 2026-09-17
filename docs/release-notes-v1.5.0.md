# WebTransport 1.5.0

Both libraries, one tag, one artifact each: **WebTransport 1.5.0** ships the Swift package
and the portable C99 library built for Apple Silicon (arm64), with a `.sha256` beside each
archive. This release carries the third audit pass's fixes — several of them wire-visible —
and two corrections to how the C99 tools negotiate flow control.

## Wire-visible fixes in this release

- **A Retry packet's `Unused` field is ignored, as the RFC requires.** RFC 9000 section
  17.2.5 gives a Retry an `Unused (4)` field whose value "is set to an arbitrary value by
  the server" and which "a client MUST ignore". Both implementations required it to be
  zero, so each refused RFC 9001 appendix A.4's own Retry — which begins `0xff` — and with
  it every Retry a conformant server writes with those bits set. Fixed in both, asserted
  against the RFC's own extracted packet.
- **The Swift Retry Integrity Tag is now computed and verified** (RFC 9001 section 5.8).
  It was parsed and never checked, so a caller that treated `decode` as validation would
  accept a forged Retry. `QUICRetryIntegrityTag` holds the section's fixed key and nonce,
  and the verifying decode needs the original Destination Connection ID — which is
  authenticated by the tag but never appears in the packet.
- **A received HTTP/3 SETTINGS payload is validated** (C99). A SETTINGS frame carrying a
  duplicate identifier was accepted and delivered; RFC 9114 section 7.2.4 says the same
  identifier MUST NOT occur more than once and permits `H3_SETTINGS_ERROR`, which is now
  what it gets.
- **The C99 tools negotiate flow control, and ignore the capsules when they have not.**
  Draft-ietf-webtrans-http3-16 section 5.1 makes flow control conditional and says an
  endpoint that did not negotiate it MUST ignore the flow-control capsules. The tools
  applied them unconditionally; they now advertise the three settings and honour the rule.
- **Swift runtime:** an unknown or reserved unidirectional stream type is ignored instead
  of being reported as a session error (RFC 9114 section 6.2 — "MUST NOT consider unknown
  stream types to be a connection error of any kind"); an over-limit flow-control capsule
  arriving on the CONNECT stream closes the session with `WT_FLOW_CONTROL_ERROR` as section
  5.6.2 requires; a second control or QPACK stream raises `H3_STREAM_CREATION_ERROR`; and
  critical-stream retention is bounded to the connection's entitlement instead of growing
  without limit.

## What changed for a caller

New public Swift API, all additive:

- `QUICRetryIntegrityTag` — `key`, `nonce`, `compute(pseudoPacket:)` and
  `verify(pseudoPacket:integrityTag:)`, the last going through `AES.GCM.open` so the
  comparison is the platform's constant-time authentication.
- `QUICRetryPacket.unusedBits`, and
  `QUICRetryPacket.decode(_:originalDestinationConnectionID:integrityTagVerifier:)`, which
  returns a packet only when its tag validates.
- `QUICRetryPacket.encodedWithoutIntegrityTag()` and
  `integrityPseudoPacket(originalDestinationConnectionID:retryPacketWithoutIntegrityTag:)`.
- `WebTransportNetworkRuntimeError.connectionTransportFailed(role:domain:code:)`, so a
  transport failure on a connection the runtime had already taken on is named as that
  rather than as an establishment failure.

One declaration changed form and no caller can tell: the session manager's eleven
collection properties are `public internal(set) var` rather than `public private(set) var`.
The setter was never visible outside the module and still is not; the in-module setter is
what let the type be split across files without changing its copy semantics.

## Repository and gates

No source file in the repository is 1,000 lines or more — the largest is 996, down from
4,154 — and the split moved code rather than rewriting it: the Swift suite is unchanged at
**376 tests, 0 failures**, and the C99 CTest name list is byte-identical at **97 tests**,
with the per-binary check counts unchanged in the binaries the splits touched.

- Swift: `swift test` under `-warnings-as-errors -strict-concurrency=complete
  -require-explicit-sendable`, plus ASan and TSan, the formatter over both manifests, the
  API-compatibility consumer build, `check-manifest-sync.sh`, `check-target-imports.sh` and
  `check-version-sync.sh`.
- C99: Debug, Release and ASan+UBSan, each **97/97**; `check-cppcheck.sh`; the Clang Static
  Analyzer over 106 sources with no findings; `check-matrix.sh`; `check-portability.sh`;
  the Windows cross-compile and the mingw `-Werror` link; and `wt-conformance-c99
  --scenario all` at **55/55**.
- CI on the released commit: C99 CI (macOS, both Ubuntu legs, Debian 13, Wine, and the
  **enforced** native Windows leg), Swift CI, and the security scan — all green.

## What is not in this release

- **0-RTT and session resumption** are not implemented.
- **The HTTP/2 capsule binding** is not implemented; this is WebTransport over HTTP/3.
- **Server push and connection migration** are out of scope for this implementation.
- The Swift package is macOS-only and needs macOS 26+, Xcode 27 and Swift 6.4; the shipped
  binaries are arm64 only.

## Checks that ran elsewhere, and what did not run

The C99 interop matrix against independent implementations was re-run for this release and
**reproduces 5 of the 7 proofs, not 7**. The certificate half of that environment was
repaired during the same work — the certificate for `pummelchen.91.99.176.243.nip.io` is
now issued and renewed automatically, and the five peer containers could be restarted with
it for the first time since the old certificate was lost — but the **erlang-webtransport
peer fails with `status=trust`** while the other four accept the same certificate files.
An RSA certificate was tried on the theory that the peer needed one; it made the *other
four* fail, so key type is excluded, and the cause is that peer's own TLS handling. The
tracker records it as `WT-196` with the next steps, and the README's "seven Phase 11
proofs" claim is not reproducible until it is fixed.

Not run here, and reported as not checked rather than assumed: the Wine suite runs on the
Linux CI host (Wine is not installable on this machine), the FreeBSD suite is a by-hand
measurement on a real kernel, and there is no LeakSanitizer on Darwin.

## Checksums

```
WebTransport-swift-1.5.0-macos-arm64.tar.gz
  SHA256: SHA256_PENDING
  Bytes:  ARCHIVE_BYTES_PENDING

WebTransport-c99-1.5.0-macos-arm64.tar.gz
  SHA256: C99_SHA256_PENDING
  Bytes:  C99_ARCHIVE_BYTES_PENDING
```
