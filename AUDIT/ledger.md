# Audit ledger — `audit/2026-09-15`

Machine-readable twin: `AUDIT/ledger.json`. The ledger wins on any conflict with the wiki.
Protocol: pre-production audit, Phases A–E (§0–§12 of the audit brief).

Base commit: `196324e` (main). Branch: `audit/2026-09-15`. **Landed on `main` at `6607d71`**
(merge commit, 2026-09-16), owner-directed after Phase E passed.

> **Branch-policy note (§0 vs. standing instruction).** The repository's standing instruction was to
> commit every major task directly to `main`. This audit's brief forbids that (§0: "Never commit
> directly to main/master/release", "Work only on branch `audit/<date>`"). The audit brief is the later
> and more specific instruction, so it won for the duration: **all audit work stayed on
> `audit/2026-09-15`**, and Phase E was complete before any of it reached `main`. Rollback for the
> branch creation is `git branch -D audit/2026-09-15` (printed here before any destructive-looking
> operation, per §0).
>
> **How it landed.** The owner directed a full sync ("push all to git so the code is in sync"), which is
> the standing instruction reasserting itself now that the audit is closed, so the branch was merged into
> `main` rather than left for a PR: `git merge --no-ff audit/2026-09-15` at `6607d71`. One conflict was
> resolved deliberately — `.github/traffic.json` (the "Views (14d)" badge's committed data source) was
> deleted by `F-repo-ops-14` and hand-refreshed on `main` by `b526c9e` ("18" → "56"). That manual edit is
> exactly the hand-maintenance the finding describes, so the deletion stands and a live endpoint is the
> way to bring the badge back. The merged tree is byte-identical to the audited branch tree, and both
> suites were re-run on it before the push: Swift **360 tests, 0 failures, 0 warnings**; C99
> **97/97 CTest**, 0 warnings.

## Status board

| id | sev | project | title | status |
| --- | --- | --- | --- | --- |
| A-0001 | S0 | swift | Swift test bundle fails to LINK on Swift 6.4 (missing WebTransportTLSCore dependency) | AUDIT (fix b80d876) |
| A-0002 | S2 | repo | Committed CMake build output at the repository root (`build/`) | START |
| A-0003 | S3 | swift | Two Swift manifests — INTENDED split, enforced by check-manifest-sync.sh | DONE (not a defect) |
| A-0004 | S1 | swift | Baseline warning count (earlier figure withdrawn as a misread); warnings-as-errors per §1 | START |
| A-0006 | S1 | swift | No check that target imports are covered by declared dependencies (A-0001 class) | START |
| F-swift-architecture-01 | S0 | swift | Unbounded peer-controlled CONNECT-stream capsule buffer | AUDIT (fix 81043ae) |
| F-swift-architecture-02 | S1 | swift | waitForReady leaks its checked continuation and connection observer on timeout | AUDIT (fix d33d1fe) |
| F-swift-architecture-03 | S1 | swift | datagramsUsable returned a constant true, so datagramsAvailable and echo claimed an unnegotiated capability | AUDIT (fix f4a9424) |
| F-swift-architecture-04 | S1 | swift | receive(maximumBytes:) ignored its bound on a buffered initial payload | AUDIT (fix 02745a9) |
| F-swift-architecture-05 | S1 | swift | magic 16 sentinel silently overrode an explicit maxConcurrentConnections: 16 | AUDIT (fix 649b14d) |
| F-swift-line-security-01 | S1 | swift | Session teardown resets and stops every associated stream regardless of which half this endpoint owns | AUDIT (fix bf6ff0c) |
| F-swift-line-security-02 | S1 | swift | Short-header reserved bits are never validated, although the long-header and Retry decoders do validate them | AUDIT (fix 1f0077c) |
| F-swift-line-security-03 | S1 | swift | Per-connection inbound-stream queue has no bound and post-establishment unidirectional streams have no consumer | AUDIT (fix 3ac7baf) |
| F-01 | S0 | c99 | QPACK static table truncated at the RFC line wrap; --check could not catch it | AUDIT (fix 03c65f0) |
| F-02 | S0 | c99 | :protocol token constants identical, so webtransport-h3 neither sent nor accepted | AUDIT (fix 448190e) |
| F-03 | S0 | c99 | Stream-table reclaim decremented the ID-issuing counters | AUDIT (fix 8946cfd) |
| F-repo-ops-02 | S1 | c99 | Interop matrix must be re-run now that the client sends webtransport-h3 | BLOCKED (needs VPS approval) |
| A-0007 | S3 | swift | Manifests not swift-format clean; CI format gate excludes them | START |
| A-0005 | S3 | swift | `swift-tools-version: 6.3` vs mandated Swift 6.4 | SUPERSEDED (6.4 baseline landed; see Round 14) |
| F-repo-ops-21 | S2 | repo-ops | Windows cross-compile sweep named private include dirs by hand: first real CI run failed on the audit's own F-28 test | AUDIT (fixed) |
| F-repo-ops-22 | S2 | repo-ops | Wine runner's check total never matched (anchored pattern vs CRLF): "0 checks", and 91,674 was never a number the runner produced | AUDIT (fixed) |
| F-repo-ops-20 | S3 | repo-ops | The Swift tree's Linux boundary was asserted, not measured: Swift 6.4 on the VPS builds 2 of 11 library targets | DONE (install + matrix) |

## Task records

_(one entry per task; fields per §8)_

## Phase A artifacts

- `AUDIT/environment.md` — hosts, toolchain versions, install commands.
- `AUDIT/inventory.md` — §2 scope discovery (pending).
- `AUDIT/baseline.md` — §3 baseline per project and per host (pending).

## BLOCKED

| item | reason | options |
| --- | --- | --- |
| valgrind (Darwin/arm64) | no arm64 macOS build exists | (1) ASan/LSan+UBSan in a Debian container locally (done — Phase E); (2) the VPS for a second Linux host (done — `F-repo-ops-19`, and the VPS also carries the Swift-on-Linux probe, `F-repo-ops-20`) |

## Round 1 progress (goal round 1/256)

All four S0 findings are fixed and verified: `A-0001` (Swift 6.4 link failure), `F-swift-architecture-01`
(unbounded capsule buffer), `F-01` (QPACK static table truncated at the RFC wrap), `F-02` (:protocol token),
`F-03` (stream-table counters). Sixteen of the S1 findings are fixed: the Swift architecture set
(`F-swift-architecture-02..05`), the Swift line/security set (`F-swift-line-security-01..03`), the Swift
test/CI set (`F-swift-perf-tests-07/08`, `A-0006`, `F-repo-ops-01`, `A-0004`), and the C99 set
(`F-04..F-08`, `F-28`). Every fix carries a test that failed before it and passes after, the suites are green
(Swift 318 tests; C99 97/97 CTest), and the Swift clean build went from 24 warnings to 0 with warnings-as-errors
enabled. Two follow-on items were filed from the fixes' residual doubt (`F-swift-line-security-04/05`), and
`F-repo-ops-02` is BLOCKED on VPS approval to re-run the third-party interop matrix now that the C99 client
sends `webtransport-h3`.

Remaining: 5 S1 (one blocked), 47 S2, 26 S3.

## Round 13 — the Swift-on-Linux boundary, measured (`F-repo-ops-20`, S3)

Committed at `d1c4b78` on `audit/2026-09-15`. The owner asked for Swift 6.4 from swift.org on the VPS.
The toolchain is installed there and, more usefully, it turns Phase E's blanket "Swift cannot run on
Linux" into a per-target measurement.

- **Installed, signature-verified**: `swift-6.4.0-RELEASE-debian13.tar.gz` (sha256
  `b623947404e7ea9843cfc315ed8624e85410fae571eb353339780ed222243737`), GPG `GOODSIG` from
  `52BB7E3DE28A71BE22EC05FFEF80A866B47A981F` ("Swift 6.x Release Signing Key"), extracted to
  `/opt/swift-toolchains/swift-6.4.0-RELEASE-debian13` behind a version-independent `swift-6.4`
  symlink with `/usr/local/bin/{swift,swiftc,swift-format,sourcekit-lsp}` repointed. `swift-6.3.2`
  stays installed. The whole install is one reproducible block in `AUDIT/environment.md`.
- **Verified working**, not just present: `swift --version` = 6.4 on `x86_64-unknown-linux-gnu`, a
  Foundation program compiles and runs, and `swift package init` + `build` + `run` print
  `Hello, world!`.
- **Measured boundary**: of the 11 library targets in `Swift/`, exactly two build on Linux —
  `WebTransportQUICCore` and `WebTransportHTTP3Core`, both with **0 warnings** under
  `.strictMemorySafety()` and warnings-as-errors. The other nine each fail on a named Apple module:
  `Darwin` (UDP backend, loopback test support), `CryptoKit` (CryptoApple, TLSCore, TestSupport) and
  `CoreFoundation` through the `WebTransportSecurityShim` C header (the shim itself, and behind it the
  public `WebTransport`, `WebTransportNetworkRuntime` and `WebTransportCLIConformance`). Logs under
  `/var/wt-swift-linux-probe/out/`.
- **What this changes**: the wiki's `Known-Limitations.md` now states the measured boundary instead
  of a blanket claim, and `AUDIT/phaseE.md`'s independent-host gap says exactly how much of the Swift
  product a Linux host can carry. **No Linux CI leg is added** by this row: the portable surface is
  two targets with no test target of its own, so a leg is a separate design decision rather than a
  YAML edit.

Ledger: **106 entries — 97 AUDIT (fixed + verified), 9 DONE, 0 open, 0 blocked**; one of the nine DONE
rows, `F-swift-line-security-05b`, was rejected with a measurement and then implemented at the owner's
request.

Verification for this round: the toolchain was exercised, not just installed (see above); the audit
branch is pushed to `origin` at `c51783b` and the wiki at `3964900`, and both remote refs match the
local trees; the CI's own secret scan,
`gitleaks git --no-banner --redact --config .gitleaks.toml .`, reports **no leaks found over 628
commits**, so the new entries (a public sha256 and a public PGP fingerprint, no secret) are clean.
The workflows run on `main` and on pull requests only, so a push to `audit/2026-09-15` starts no CI
job; the local scan is the check that counts.

## Landing — the audit on `main` (`6607d71`, then `edfc57a`)

The owner directed a full sync, so the audited branch was merged into `main` (see the branch-policy
note at the top for why the PR step was replaced and how the one conflict was resolved). What changed
with the landing:

- `main` now carries the whole audit: the 97 verified fixes, the `AUDIT/` evidence tree, the blocking
  secret/CVE scan workflow, the removed committed build output and the third-party notice.
- The merged tree is byte-identical to `audit/2026-09-15`'s tree, and it was re-verified before the
  push rather than assumed: `swift build --build-tests` + `swift test` on the root package —
  **360 tests, 0 failures, 0 warnings**; `cmake` configure/build (Ninja, Release) + `ctest` on C99 —
  **100% tests passed out of 97**, 0 warnings.
- `CHANGELOG.md`'s `[Unreleased]` section now records what a caller and an operator can observe from
  the audit — the new unidirectional-stream API, the capability and bound corrections, the Swift and
  C99 security fixes, the CLI and CI changes and the badge removal — with the ledger named as the
  complete list. The audit had not touched the changelog, which is a documentation gap that only
  mattered once the work reached `main`.
- `audit/2026-09-15` and `main` are kept identical (the branch was fast-forwarded to the landing
  commit), so there is no divergence to reconcile later and no stale copy of these documents.

### Second merge — `main` moved while the landing was in flight (`edfc57a`)

The push of the landing was rejected because `main` had advanced: **node4 pushed three commits**
(`15d37bf`, `21e7bce`, `0255595`) that did part of the same work the audit had done, independently —
the Swift 6.4 test-bundle link failure (`A-0001`) and the 12 redundant `unsafe` effect markers
(`A-0004`) — and went further by **raising the toolchain baseline itself**: `swift-tools-version: 6.4`
in both manifests, `Swift/check-toolchain.sh` at Swift 6.4 / Xcode 27, and the three macOS jobs on the
`xcode-27` image. The merge is `edfc57a`; six files conflicted and each was resolved on its merits:

| File | Resolution |
| --- | --- |
| `Package.swift`, `Swift/Package.swift` | Take `swift-tools-version: 6.4`, with a comment recording that it supersedes `A-0005`; keep node4's explanation of why the 6.4 build system needs the `WebTransportTLSCore` test dependency explicit, plus the audit's cross-manifest note. |
| `Swift/check-toolchain.sh` | Keep the overridable floors, move the default from 6.3.3 / 26.6 to 6.4 / 27.0: the development floor and the mandate are one toolchain now, so the split the script documented is gone. |
| `.github/workflows/swift-ci.yml` | Keep the audit's job name and F-repo-ops-01 comment (the toolchain is what the job asserts; `runs-on` is `xcode-27` on both sides) and collapse two toolchain steps into one, since the bare call was only distinct while the default was the older floor. |
| `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift` | Keep the audit's reused receive buffer (`F-swift-perf-tests-05`) and drop the per-call `buffer`; node4's redundant-`unsafe` removal on `withUnsafeMutableBytes` is preserved. |
| `CHANGELOG.md` | Keep the audit's paragraph and its Fixed/Added/Changed entries; replace the now-obsolete "swift-tools-version stays at 6.3" bullet with node4's toolchain-baseline and CodeQL bullets, in the same `Changed` section. |

`A-0005` is recorded as **superseded, not wrong**: it asked for 6.3 to be revisited when the 6.3.3
floor moved, and node4 moved it. `1f7ee98` restores the two trailing commas the hand resolution
dropped — the audit's own `swift format lint` gate (A-0007) caught them, which is the gate working.
Re-verified on the integrated tree: `swift format lint --strict` clean, `check-manifest-sync.sh` 19
shared targets agree, `check-target-imports.sh` 42 targets / 202 imports covered, `swift test` (root)
**360 tests, 0 failures, 0 warnings**, `swift test --package-path Swift` green, C99 **97/97**, 0 warnings.

## Round 14 — the first real CI run on `main`, and what the audit's own CI additions found

Pushing the audit to `main` started CI on this tree for the first time: branch pushes trigger nothing, so every
check the audit added had only ever been run by hand. **Two defects, both in the audit's own CI additions, and
both fixed and re-measured** rather than waived:

- **`F-repo-ops-21` (S2) — all four C99 jobs failed at "Compile the Windows platform branch".** The audit's F-28
  test (`C99/tests/unit/test_time.c`) includes the private `src/core/time_internal.h` and CMake gives that test
  the include directory (`C99/tests/CMakeLists.txt:118`), so the CMake builds and the local 97/97 ctest run were
  green while the cross-compile sweep — which keeps a hand-written `-I` list — could not see the header. Reproduced
  on the VPS with mingw-w64: `time_internal.h: No such file or directory`. The sweep now scans every `src/*/`
  directory that holds a header instead of naming them, and asserts that no two private headers share a basename
  (a flat include path cannot address those), so a new private header cannot break it again. Re-measured: 76
  library sources and 108 test/app sources compile under `x86_64-w64-mingw32-gcc`, 0 warnings; the Windows link
  produces 91 PE32+ executables and 1 shared library.
- **`F-repo-ops-22` (S2) — the Wine runner's check total was always 0.** `check-windows-wine.sh` summed each
  binary's last line with a `$`-anchored pattern, and a Windows binary writes text-mode stdout as CRLF: `od -c`
  shows `passed\r\n`, so the pattern matched nothing and the runner printed `85 passed, 0 failed, 0 hung, 0 checks`
  with the misleading `85 executable(s) printed no check total (a hang or a load failure)`. Measured at the commit
  that added the summing (`a2d995e`) — the same `0 checks` — which means the `91,674` that F-21 added the summing
  *to produce* was never produced by any revision: it was a hand-added number, and it had spread to
  `C99/docs/PORTABILITY.md`, `C99/scripts/score-matrix.sh` and `C99/IMPLEMENTATION_PLAN.md`. The runner now reads
  the output through `tr -d '\r'`, a missing total **fails** the run instead of counting as zero checks (the same
  floor F-25 put one level down in `WT_TEST_MAIN_END`), and the documents carry the measured numbers rather than
  the drifted one: **64,900 checks over 85 executables under Wine**, **64,778 over 84 programs natively on Debian
  13**, and the audit's own **64,731 on macOS 26**, each with its host named.

Neither is a product defect — the checks failed loudly, and the second one's product evidence (85 of 85 executables
passing) was never in doubt — but both are the check-integrity class this audit was about, found by the CI gates
the audit added. Ledger: **108 entries — 99 AUDIT (fixed + verified), 9 DONE, 0 open, 0 blocked.**
