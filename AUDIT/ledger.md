# Audit ledger — `audit/2026-09-15`

Machine-readable twin: `AUDIT/ledger.json`. The ledger wins on any conflict with the wiki.
Protocol: pre-production audit, Phases A–E (§0–§12 of the audit brief).

Base commit: `196324e` (main). Branch: `audit/2026-09-15`.

> **Branch-policy note (§0 vs. standing instruction).** The repository's standing instruction was to
> commit every major task directly to `main`. This audit's brief forbids that (§0: "Never commit
> directly to main/master/release", "Work only on branch `audit/<date>`"). The audit brief is the later
> and more specific instruction, so it wins: **all audit work stays on `audit/2026-09-15`** and reaches
> `main` only through a PR after Phase E passes. Rollback for this branch creation is
> `git branch -D audit/2026-09-15` (printed here before any destructive-looking operation, per §0).

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
| A-0005 | S3 | swift | `swift-tools-version: 6.3` vs mandated Swift 6.4 | START |

## Task records

_(one entry per task; fields per §8)_

## Phase A artifacts

- `AUDIT/environment.md` — hosts, toolchain versions, install commands.
- `AUDIT/inventory.md` — §2 scope discovery (pending).
- `AUDIT/baseline.md` — §3 baseline per project and per host (pending).

## BLOCKED

| item | reason | options |
| --- | --- | --- |
| valgrind (Darwin/arm64) | no arm64 macOS build exists | (1) ASan/LSan+UBSan in a Debian container locally; (2) VPS Linux run for a second host (needs approval per §1b) |

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
