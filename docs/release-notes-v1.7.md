# WebTransport 1.7

Both libraries, one tag, one artifact each: **WebTransport 1.7** ships the Swift package and the
portable C99 library built for Apple Silicon (arm64), with a `.sha256` beside each archive.

**There is no user-visible change in either library.** This release exists because the two libraries
always carry the same version and are republished together: the number moves so that a caller
pairing them knows the pair is compatible, not because anything about the libraries changed.
`WT_ABI_VERSION` and the protocol draft are separate axes and do not move with it.

These notes are the changelog for this release. Each change is under the library it belongs to, and
the work that is genuinely one item for both is under **Both**.

### Swift

No changes. The library is rebuilt and republished at 1.7 because the two libraries always carry the
same version.

### C99

No changes to the library. `C99/src/` is identical to 1.6, so nothing about its behaviour, its
headers or its ABI moves. What did change is its test suite, which regained coverage a refactor had
silently dropped: the `test_quic_packet` split in the 1.6 cycle discarded the pre-split file's whole
`main()` body — about 535 lines — and most of it was genuinely absent afterwards. It is restored as
four topic sources of the same test executable, so the CTest count is unchanged while the checks that
executable runs went from 81 to **212**:

- the RFC 9001 A.2 header-protection vectors, decoded and re-encoded byte for byte;
- first-byte classification (long, short, Version Negotiation, empty, NULL, three bytes);
- Handshake, Initial (300-byte token) and short-header round trips, with the short-header encoder
  now reachable from a test at all;
- the Retry round trip, its built minimum, the header-into-tag underflow regression, and the
  long-header refusal;
- the decoder refusal corpus (fixed bit, reserved bits, a 21-byte connection ID, empty input, a
  Length beyond the buffer, and every prefix of a valid packet), the ten encoder refusals, and
  coalesced-datagram walking;
- `wt_quic_packet_type_name`, which no test called before.

Two of the restored areas were confirmed able to fail before being trusted, by breaking
`C99/src/quic/packet.c`, watching the specific check fail, and restoring the source byte for byte.

Checks: `C99/scripts/build-and-test.sh` — **105 CTest tests** — a fresh scratch configure and build
with 0 warnings, `test_quic_packet` at **212/212**, and `check-format.sh` clean over all 347 C
sources.

### Both

Changed, in the release process rather than in the libraries:

- **The bump checklist is written down and enforced.** Bumping the version writes `VERSION` and the
  two mirrors, but every other reference to the version is prose, and nothing checked it — which is
  how the 1.6 release briefly left the README and the wiki naming 1.5.2. `RELEASE.md` now lists every
  document a bump must carry, and `Swift/check-version-sync.sh` checks the four repository-side ones:
  the notes file exists, the README links the release tag, the README's SwiftPM pin agrees, and
  `AGENTS.md` names the version. CI already runs that script, so forgetting one is now a failing
  gate rather than a released mistake. The wiki half of the list is marked as checked by hand,
  because the wiki is a separate repository and no gate in this one can read it.
- **The two libraries' ABI versions are compared.** They must be identical on a release, and the
  same script now fails when they differ.

Checks: `./Swift/check-version-sync.sh`, run by CI, and each of its checks was seen to fail before
being trusted.

## What is not in this release

Unchanged from 1.6 — the limitations listed in `docs/release-notes-v1.6.md` still stand, including
that 0-RTT and session resumption are not implemented, the HTTP/2 capsule binding is absent, server
push and connection migration are out of scope, and the Swift client cannot set the TLS server name.

## Checks that ran elsewhere, and what did not run

Not run on the release machine, and reported as not checked rather than assumed: the Wine suite and
the FreeBSD VM job run in CI, the macOS and Linux C99 legs and the MSVC and Clang-CL Windows legs run
in CI, `ThreadSanitizer` runs in its own CI job, and there is no LeakSanitizer on Darwin. The VPS
interop suites need the routable host and were not re-run for this release.

## Checksums

```
WebTransport-swift-1.7-macos-arm64.tar.gz
  SHA256: SHA256_PENDING
  Bytes:  ARCHIVE_BYTES_PENDING

WebTransport-c99-1.7-macos-arm64.tar.gz
  SHA256: C99_SHA256_PENDING
  Bytes:  C99_ARCHIVE_BYTES_PENDING
```
