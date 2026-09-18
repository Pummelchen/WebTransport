# Phase E — the independent-host verification

Phase E is the last thing the standard asks for and the only part of this audit that cannot be
done on the primary host. This file is the runbook for it, written now so that provisioning a
host and producing the evidence is mechanical rather than improvised.

**Status: run and passed on both hosts** (see `AUDIT/convergence.md`, "Phase E"). The owner provided two hosts on 18 September 2026, which is option (2) of the
three this file listed:

| Host | What it is | Toolchain | Why it is independent |
| --- | --- | --- | --- |
| `node1` | Mac mini M2, 8 GB, macOS 27.0 | the pinned set exactly: Swift 6.4 / Xcode 27.0 / swift-format 603.0.0 / SwiftLint 0.65.1 / clang-format 23.1.1 / cmake 4.4.3 / ninja 1.13.2 / python 3.14.7 / ruff 0.16.7 / gitleaks 8.30.1 / trivy 0.74.0 / shfmt 3.14.1 — only `cppcheck` absent | a different physical machine, and it can run both libraries, so the full 28-gate sweep runs there |
| `deltasona` | Intel VPS, Debian 13 (trixie) `x86_64`, 8 cores | gcc 14.2.0, clang 19.1.7, cmake 3.31.6, ninja 1.12.1, python 3.13.5, OpenSSL 3.5.7 — deviations from the pinned set, recorded as the runbook requires | **a different OS, kernel and architecture**, which this file says is worth more than an identical host; it can run the C99 half plus the LeakSanitizer path Darwin does not have |

Neither host was provisioned by the audit: both existed and answered an SSH key the primary host
already held. The VPS is production, so everything there happens under `/var/webtransport-phase-e/`
and nothing outside it is written or removed.

**Phase E found a defect on its first cross-platform run** — `AUD-0038`: the C99 sanitizer
configuration could not be built with gcc at all, and CI's sanitizer step was gated to clang, which
is the one leg that would have said so. Fixed on the audit branch (`f6c7879`) before the runs below,
because the runbook says a gate that fails on a second host is fixed and then re-run.

## Why the primary host cannot stand in

`AUDIT/environment.md` records the honest reason a fresh clone on `Mac14,3` is not
"independent": the point of a second host is to catch what is *inherent* to the first one --
its toolchain defaults, its cached build state, its OS behaviour, its idea of what a clean
checkout looks like. A second clone shares all of those. Calling it Phase E would satisfy the
letter of the task and defeat its purpose, which is exactly what the standard's non-negotiables
forbid.

## What the host has to be

- A different machine, not a second account or container on the primary host.
- Reachable enough to run the sweep and return its output. A different OS or kernel is worth
  more than an identical one: the C99 tree already claims Windows and FreeBSD support, and a
  Linux host exercises the sanitizer paths this host cannot (Darwin has no LeakSanitizer, and
  the C99 CI's leak findings have all come from its Linux leg).
- The pinned toolchain from `AUDIT/environment.md` installed from source or package manager as
  that platform requires. Where a pinned version is unavailable on the new platform, record the
  version actually used rather than silently substituting it.

## What to run

1. Clone the repository at the audit branch's final commit and check out exactly that commit
   (`git rev-parse HEAD` on the primary host, recorded in this file when Phase E runs).
2. `./Swift/check-toolchain.sh 6.4 27.0` where the toolchain matches, or record the deviation.
3. `AUDIT/run-sweep.sh` -- the 24 gates. Then `SWEEP_HEAVY=1 AUDIT/run-sweep.sh` for the six
   heavy gates plus the soak. The script is the same one the primary host runs, so the two
   results are directly comparable; nothing is retyped.
4. Capture the full output of both runs, unedited, alongside the primary host's
   `AUDIT/convergence.md` sweeps.

## What counts as passing

The same yardstick as the baseline, which exists for this purpose (`AUDIT/baseline.md`,
"Regression yardstick"): 0 build warnings on both sides, 401 Swift tests, 97 C99 tests,
90.74% Swift / 91.64% C99 line coverage, and no new CVE or secret findings. A gate that cannot
run on the new host is reported as **not checked**, with the reason -- never as a pass, and
never removed from the script to make the run green.

## What to do with the result

- **All gates pass:** append the run to `AUDIT/convergence.md` as "Phase E", record the host and
  its toolchain in `AUDIT/environment.md`, mark `AUD-0002` done, then render the final report
  from the ledger (§9) -- `AUDIT/render-ledger.sh` already generates `AUDIT/ledger.md` from
  `AUDIT/ledger.json`, and the report is the same table plus the tier-coverage disclosure from
  `AUDIT/inventory.md` §2.4 and the pass record from `AUDIT/passes.md`. Only then is the audit
  complete by §12: open count 0 *and* Phase E passed on an independent host.
- **A gate fails:** that is a finding, and it goes into `AUDIT/ledger.json` with a new id and
  its severity -- a defect that only appears on a second host is exactly what Phase E is for.
  Fix it on the audit branch, re-run the primary sweep, then re-run Phase E.
- **A gate cannot run:** record it as not checked with the reason. The standard is explicit that
  a check which cannot run is reported, not skipped quietly.

## The decision, taken

`AUD-0002` offered three options and the owner took the second: two existing machines were
nominated and access was provided. `node1` runs the full sweep on the pinned toolchain; `deltasona`
runs the C99 half and the script gates on a different OS, kernel and architecture. What each host
could not run is in `AUDIT/convergence.md` under "Phase E", recorded as not checked with its
reason rather than as a pass.

The audit is complete by §12: the open count is 0 and Phase E has passed on an independent host.
