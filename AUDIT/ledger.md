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
| (none yet — Phase A in progress) | | | | |

## Task records

_(one entry per task; fields per §8)_

## Phase A artifacts

- `AUDIT/environment.md` — hosts, toolchain versions, install commands.
- `AUDIT/inventory.md` — §2 scope discovery (pending).
- `AUDIT/baseline.md` — §3 baseline per project and per host (pending).

## BLOCKED

_(none yet)_
