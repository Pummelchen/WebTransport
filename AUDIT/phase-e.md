# Phase E — the independent-host verification

Phase E is the last thing the standard asks for and the only part of this audit that cannot be
done on the primary host. This file is the runbook for it, written now so that provisioning a
host and producing the evidence is mechanical rather than improvised.

**Status: not run. No independent host exists** (`AUD-0002`, BLOCKED, owner: repository owner).

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

## The decision needed

`AUD-0002` carries three options for the repository owner, and the standard says to ask before
provisioning anything:

1. Approve a VPS or CI runner and provide access.
2. Nominate an existing independent machine and provide access.
3. Accept a documented waiver that Phase E ran on the primary host only.

Until one of those happens, the audit is complete in every respect except this one, and saying
otherwise would be the kind of claim this audit exists to prevent.
