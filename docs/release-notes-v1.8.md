# WebTransport 1.8

Both libraries, one tag, one artifact each: **WebTransport 1.8** ships the Swift package and the
portable C99 library built for Apple Silicon (arm64), with a `.sha256` beside each archive.

**The protocol target moves to `draft-ietf-webtrans-http3-17`** (2 November 2026, WG Last Call) in
both libraries. The wire formats — stream types, capsules, the exporter context, the
`webtransport-h3` upgrade token — are unchanged between the drafts; what changed is the
`SETTINGS_WT_ENABLED` codepoint and the rules around it, and with them who this release can talk to.
`WT_ABI_VERSION` does not move: the additions are new declarations, not changed signatures.

These notes are the changelog for this release. Each change is under the library it belongs to, and
the work that is genuinely one item for both is under **Both**.

### Swift

- **The protocol target is draft-17.** `WebTransportVersion.protocolDraft` reports
  `draft-ietf-webtrans-http3-17`.
- **`settingsValidation` renames its strict case: `.draft16Strict` → `.draft17Strict`.** This is a
  source-breaking rename for anyone who named the case explicitly (the CLI string is now
  `draft17-strict`). The default stays the strict posture; `.interoperable` is unchanged as the way
  to serve or speak to earlier revisions, and under draft-17 it covers the pre-draft-16
  advertisements too (see **Both**).
- **§3.1 advertisement rules.** A strict client sends **no** `SETTINGS_WT_ENABLED` at all (draft-17
  gives the setting no meaning from a client); a strict server advertises the §9.2 codepoint
  (`0x20b8933b`) with the value 1. A server's SETTINGS carrying a value greater than 1 is the
  H3_SETTINGS_ERROR connection error §3.1 names, from either direction.
- **§5.5 with §5.6.2/§5.6.4: the flow-control baseline is anchored to the peer's SETTINGS.** While
  no `WT_MAX_DATA` / `WT_MAX_STREAMS` capsule of a type has been received, the peer's
  `SETTINGS_WT_INITIAL_MAX_*` value stands in for "the value previously received", and a capsule
  that does not increase it — **including one equal to it** — closes the session with
  `WT_FLOW_CONTROL_ERROR`. The settings already granted that value; the first capsule must exceed it.
- **§4.4: a reset whose error code falls outside the `WT_APPLICATION_ERROR` range still resets the
  stream but maps to no application error code** — delivered as a reset with no application error
  code, never a session error. `WebTransportDraft17ErrorMapper.receivedApplicationErrorCode(forHTTPErrorCode:)`
  returns `nil` for such codes.
- **New public surface:** `WebTransportPeerAdvertisedVersion` and
  `HTTP3Settings.webTransportAdvertisedVersion()` (which era's rules a peer's SETTINGS select),
  and `WebTransportFlowControlState.refusesRepeats` (the era's refusal rule, seeded from the
  negotiation). Buffered-stream rejection gained a pin asserting it never affects the session the
  stream was meant for (§4.6).

Checks: the full package suite (403 tests, 0 failures), both CLI conformance suites **40/40**,
`swift format --strict`, `check-version-sync`, `check-api-compatibility`, the library smoke pair,
`check-manifest-sync`, and the CI legs (ASan suite, TSan, the 20000-iteration fuzz, DocC). The
Swift client completed **7 of 7** interop proofs against the five independent implementations on
the routable host (13 November 2026), all under `--trust system`.

### C99

- **The protocol target is draft-17.** `wt_protocol_draft()` reports
  `draft-ietf-webtrans-http3-17`; `WT_HTTP3_SETTING_WT_ENABLED` is the §9.2 codepoint `0x20b8933b`,
  and the draft-16 codepoint `0x2c7cf000` stays recognised as
  `WT_HTTP3_SETTING_WT_ENABLED_DRAFT16`.
- **§7.1 selection is a library surface, not a tool detail.** New:
  `wt_webtransport_version_profile_t` (`WT_WEBTRANSPORT_PROFILE_DUAL`, the default, and
  `_FINAL`), `wt_webtransport_version_t` (`_FINAL`, `_DRAFT16`, `_LEGACY`),
  `wt_webtransport_settings_apply_profile()`, `wt_webtransport_version_select()` (server),
  `wt_webtransport_client_version()` (client), and
  `wt_webtransport_peer_advertised_version()` (role-free classification). A DUAL endpoint
  advertises both codepoints; a FINAL endpoint advertises the §9.2 codepoint alone, and a FINAL
  client sends none.
- **§4.4: a reset whose error code falls outside the `WT_APPLICATION_ERROR` range is delivered as
  the new sentinel `WT_SESSION_RESET_NO_APPLICATION_ERROR`** (`include/webtransport/api/events.h`)
  — the stream is still reset, with no application error code, and never a session error.
- **The CLI tools default to the DUAL posture** and grow `--wt-enabled dual|final` for the strict
  one; `--upgrade-token` is unchanged.
- **The conformance catalog renames its thirteen `draft16-*` scenario IDs to `draft17-*`**, and the
  compliance matrix measures **42 of 43** draft-17 requirements (the one `partial` is Origin
  policy, which the library exposes and leaves to the application, as before). Three rows are new
  and tested: the §7.1 selection, the §5.5 SETTINGS baseline, and the §4.4 no-application-code
  reset.

Checks: `C99/scripts/build-and-test.sh` — **105 CTest tests** — under ASan+UBSan, a fresh scratch
build with 0 warnings, `check-format.sh` clean over all 347 C sources under the pinned
clang-format 23.1.5, `check-vectors.sh`, and the 57-scenario conformance tool at **57/57** with the
renamed IDs. The C99 client completed **7 of 7** interop proofs against the five independent
implementations on the routable host (13 November 2026), and the server direction — the
pywebtransport and quic-go clients against `wt-server-c99` — completed **2 of 2**. The tree also
builds and passes the full suite under **OpenSSL 4** (measured 13 November 2026, homebrew
`openssl@4`), which the macOS CI leg now ships by default; the CI cover leg runs the same suite on
Debian, FreeBSD, Wine and the native Windows compilers.

### Both

- **§7.1 version selection, with a LEGACY answer.** Both libraries implement the draft's version
  selection: the §9.2 codepoint a client sends selects the final version; the draft-16 codepoint
  selects draft-16; and the earlier drafts' advertisements (`0x2b603742`, `0xc671706a`) — which is
  what **every** pre-draft-16 implementation this tree interoperates with actually sends, captured
  from the wire on 13 November 2026 — select a LEGACY session. The selection changes only
  advertisement and validation: the wire formats are identical across the drafts, so one code path
  serves every peer. The flow-control refusal rule follows the negotiated version — the SETTINGS
  baseline is a FINAL-session rule, and a DRAFT16 or LEGACY session runs its era's own rule, where
  a repeat of the received grant is legal and only a grant that goes backwards closes the session.
  This is measured, not designed: the first cross-test on the draft-17 tree failed **5 of 7**
  client proofs precisely because the old client-side gate refused the peers' legacy
  advertisements and the draft-17 flow rule closed sessions the peers considered healthy.
- **The version moves to 1.8 in lockstep** — both libraries rebuilt and republished at the same
  number, because a caller pairing them has no other way to know the pair is compatible. The
  protocol draft is a separate axis and moves to -17 in both; `WT_ABI_VERSION` stays at 2.

## Checks that ran elsewhere, and what did not run

Not run on the release machine, and reported as not checked rather than assumed: the Wine suite,
the FreeBSD VM job, the Debian 13 leg, and the MSVC and Clang-CL Windows legs run in CI;
`ThreadSanitizer` runs in its own CI job; there is no LeakSanitizer on Darwin.

**The connection-churn soak's scheduled runs produced no verdict, so the release machine ran the
same script.** Its two scheduled runs (12–13 November) established no sessions at all — flat
memory and thread profiles, the run's own verdict "no sessions were established — the run proved
nothing" — which is a runner-side failure of the harness, not a measurement. The release machine's
run (`./Swift/run-soak.sh`, 13 November 2026) established **400 of 400** connections and passed:
no sustained growth in resident memory or thread count. The leak-watch is checked for 1.8, on the
release machine rather than in CI, and the CI leg's empty runs are named here rather than counted
as either pass or fail.

Browser sessions with Chrome were not re-run for this release. Chrome is a draft-16-era peer;
serving it is `.interoperable`'s contract, and the legacy-advertisement acceptance this release
adds is measured against the aioquic-based peer of the same era — but a live Chrome session is a
check that did not run, and it is named as one.

## Checksums

```
WebTransport-swift-1.8-macos-arm64.tar.gz
  SHA256: SHA256_PENDING
  Bytes:  ARCHIVE_BYTES_PENDING

WebTransport-c99-1.8-macos-arm64.tar.gz
  SHA256: C99_SHA256_PENDING
  Bytes:  C99_ARCHIVE_BYTES_PENDING
```
