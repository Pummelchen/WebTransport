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
