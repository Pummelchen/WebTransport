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
| A-0001 | S0 | swift | Swift test bundle fails to LINK on Swift 6.4 (missing WebTransportTLSCore dependency) | START |
| A-0002 | S2 | repo | Committed CMake build output at the repository root (`build/`) | START |
| A-0003 | S2 | swift | Two Swift manifests, different names and target counts (18 vs 21) | START |
| A-0004 | S1 | swift | 25 baseline warnings; §1 mandates warnings-as-errors | START |
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
