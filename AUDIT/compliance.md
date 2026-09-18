# AUDIT — compliance with the standard's own process rules

The other AUDIT files record what was found. This one records whether the *rules about how the
audit is run* were followed, including the two places they were not, because a compliance
record that only lists successes is the same kind of document as a check that cannot fail.

## §0 — non-negotiables

| Rule | How it was verified |
| --- | --- |
| Never weaken a check | No test deleted, no assertion loosened, no `catch` broadened, no `type: ignore`/`!`, no `#pragma`/`-Wno-` added, no threshold raised, no file excluded from analysis. The four SwiftLint rules disabled in `.swiftlint.yml` are the only suppressions and each is a numbered task (AUD-0012…0016) with its evidence. |
| Work only on `audit/<date>` | `git branch --show-current` is `audit/2026-09-18` for every commit of this audit. |
| Never commit to `main` | `main` is still at `397b047`, the commit recorded as the baseline; `git log <merge-base>..main` is empty. |
| Never force-push or rewrite history | No `--force`, no `push --delete`, no history rewrite on the audit branch. One rebase onto a remote commit happened during the *1.5.1 release* work before the audit began, recorded at the time. |
| Never touch live systems | Nothing was deployed or provisioned. Phase E's host was never created because the standard requires asking first (`AUD-0002`). |
| Never print, log or commit a secret | `gitleaks git` over the full history reports no leaks; the GitHub token used for the pre-audit release work was passed inline through the environment only, is in no file, no config and no commit, and its rotation is noted for the owner. |
| Report only `file:line contains a live-looking credential` | No live credential was found, so no such line exists to report. |
| No scope-narrowing to close a task | Every task's `fix_summary` names what was changed, and the sweeps re-run the whole gate set rather than the subset a change touched. |
| If in doubt, write the doubt down | `AUDIT/convergence.md` carries the two near-misses (a generated file broken by the reformat, a soak nobody ran); this file carries the two process deviations below. |

## §1 — the build-configuration mandate: **one deviation, recorded**

The standard asks for the language standard to be enforced in the build configuration rather than on
a command line that happens to pass it. Two of the three Swift settings are there:
`strictSwiftSettings` in both manifests carries `.strictMemorySafety()` and
`.treatAllWarnings(as: .error)`, so a new warning fails `swift build` for a contributor and for CI
alike.

**`-require-explicit-sendable` is not, and cannot be.** SwiftPM exposes no first-class SwiftSetting
for it (checked against `PackageDescription`'s own interface for tools 6.4: there is
`strictMemorySafety`, `treatAllWarnings`, `swiftLanguageMode`, `unsafeFlags` and no equivalent). The
only mechanism is `.unsafeFlags`, and SwiftPM refuses a dependency that uses unsafe build flags —
for **remote** dependencies only, which is the part that makes a local check impossible: a `file://`
URL is resolved as a local dependency, so a versioned-consumer check in this repository builds
happily with `.unsafeFlags` present. That was implemented, measured and dropped rather than shipped
as a check that could not see what it claimed to.

The result is that the flag stays on the CI command line and this file records the deviation. The
alternative — putting it in the manifest — breaks the package for every consumer that reaches it by
version, which is worse than the deviation it would remove. `AUD-0008` carries the experiment.

## §7 — severity ordering: **one deviation, recorded**

The standard says findings are fixed in severity order S0 → S3. Two S2 tasks were closed while
the S1 finding `AUD-0006` was still open: `AUD-0009` (C99 coverage) in the second round and
`AUD-0017` (the API-compatibility blind spot) in the fourth.

The reason is not a defence: `AUD-0006` was a 556-finding remediation that spanned fourteen
rounds, and the two S2 tasks were independent of it. Closing them kept the ledger's open count
moving instead of frozen behind one large task. The S1 was being worked continuously throughout
— 29 commits name it — so nothing higher-severity was left idle. But the ordering rule is a
rule, and working S2 before an open S1 is a deviation from it. It is recorded here rather than
justified away, and the two tasks it affected are named so a reviewer can look at exactly those
rounds.

## §8 — the ledger's own shape: a gap found and closed

The ledger is the single source of truth, which only works if its shape is checked. Eleven
`DONE` tasks had **no commit recorded**, so the record said a finding was fixed and could not
say where — most of them closed before recording the hash became routine.

`AUDIT/check-ledger.py` now enforces §8's rules mechanically: every task carries its required
fields, ids are unique and well-formed, severities and statuses are from the allowed sets, a
`DONE` task has a fix, evidence and a commit, and a `BLOCKED` task has a named owner and at
least two options. The missing commits were backfilled from the commits that delivered each
task (`AUD-0001`, `0003`, `0004` and `0011` came from the Phase A commit `5265558`; the rest
from their own).

Proven in both directions, like every other gate here: with a `DONE` task's commit emptied it
reports `AUD-0005: DONE but 'commit' is empty`; with `AUD-0002`'s reason replaced by a sentence
naming no owner it reports both the missing owner and the missing options; restored, it reports
`19 tasks valid`. It is in `AUDIT/run-sweep.sh`, so every future sweep checks it.

## §9 — the report comes from the ledger

`AUDIT/render-ledger.sh` generates `AUDIT/ledger.md` from `AUDIT/ledger.json`, and nothing in it
is edited by hand. The final report adds the tier-coverage disclosure (`inventory.md` §2.4) and
the pass record (`passes.md`); the runbook for producing it is in `phase-e.md`. It is not
produced yet, because §12 makes it contingent on Phase E.

## §10 — one task per commit: **one deviation, recorded**

No commit on this branch names more than one task id, so no two tasks were bundled. The
deviation is the other direction: `AUD-0006`, an S1, was delivered in **29 commits** rather than
one. A single commit carrying 556 findings across 34 files would be unreviewable, so it was
split into the focused units the rule exists to produce — one per group of findings, each with
its own evidence and its own green suite. The rule's purpose is met; its letter is not, and the
count is recorded here so the difference is visible.

## §11 — phases

| Phase | State |
| --- | --- |
| A — toolchain, inventory, baseline, ledger | Complete. `environment.md`, `inventory.md`, `baseline.md`, `ledger.json` |
| B — the passes and the fixes | Complete. `passes.md` (L0–L7 plus §5 and §6) |
| C — drain S2/S3 | Complete: 17 tasks done, 0 open |
| D — convergence sweeps | Complete: four sweeps, the last adding no task (`convergence.md`) |
| E — independent host | **Not run.** No host exists; the standard says to ask before provisioning one (`AUD-0002`, three options recorded) |

## §12 — the completion condition

Not met, and not claimed: §12 requires the open count to be exactly **0** *and* Phase E to pass
on an independent host. The count is 0; Phase E has not run. Saying the audit is complete would
be the kind of claim this audit exists to prevent.

## §13 — report format

Used for every round report: `[#<id> <n>/<total> | done:<d> open:<o> blocked:<b> new:<x>] <STATUS> — <title>`,
with the numbers read from the ledger rather than from memory.
