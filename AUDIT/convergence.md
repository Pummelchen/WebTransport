# Convergence sweeps

The audit standard makes the ledger's own count the completion gate, which only means
something if the sweep that produced it can be run again and give the same answer. This file
is the log of those runs: what was run, on which host, and what it found.

`AUDIT/run-sweep.sh` is the sweep. Every entry in it is the command the corresponding CI
workflow runs, so a green sweep here is a statement about the gates that matter rather than
about a remembered subset. Run it as `AUDIT/run-sweep.sh`, and with `SWEEP_HEAVY=1` to add the
expensive gates listed at the bottom.

A sweep's job is to find work, and it is only useful if a clean result is reported as clean and
a dirty one as dirty. Both happened, which is why this file records two runs rather than one.

## Sweep 1 — primary host, `Mac14,3`, macOS 27.0

24 gates, **1 failed**:

| Gate | Result |
| --- | --- |
| All 13 Swift gates (toolchain, manifests, version lockstep, unsafe flags, target imports, both linters, strict build, API compatibility, tests, PKCS#12, nested test target, library smoke) | PASS |
| All 8 C99 gates except the vectors check | PASS |
| `RFC vectors match the documents` | **FAIL** — `C99/src/http3/qpack_huffman_table.h` did not match the RFC extractor |
| Both security gates (gitleaks over full history, trivy) | PASS |

The failure was mine, and it was introduced by AUD-0010 in the same round: the reformat
excluded the generated headers under `tests/vectors/` but missed the two that the extractors
render into the library itself — `src/http3/qpack_huffman_table.h` and
`src/http3/qpack_static_table.h`. `clang-format` rewrote the first one (152 insertions, 517
deletions) and the generator's byte comparison no longer matched.

Two things are worth recording about that:

1. **`check-vectors.sh` caught it, not the formatting gate.** The exclusion list in
   `check-format.sh` was the thing that was wrong, and it could not catch its own mistake. The
   independent check that owns those bytes is what noticed. That is the argument for keeping a
   second check on generated output rather than trusting the list of files a formatter skips.
2. **AUD-0010's recorded evidence was incomplete.** It said the generated vectors were
   untouched, which was true of `tests/vectors/` and false of the header in `src/`. The ledger
   entry was corrected rather than left standing; the tree was restored to the generator's
   bytes and `check-format.sh` now excludes both paths explicitly, with the reason.

## Sweep 2 — primary host, after the fix

24 gates, **0 failed**.

The only change between the two runs is the restored generated header and the corrected
exclusion list, which is the point — the sweep that finds nothing has to be a sweep that would
have found the thing it found last time.

## Between sweeps 2 and 3: the L5 pass added a task

The sweep is not the only discovery instrument, and this is the round it showed. Running the
L0–L7 passes (`AUDIT/passes.md`) required the performance pass to produce evidence rather than
an opinion, which meant running the repository's own resource harness. `Swift/run-soak.sh`
passed — 400/400 connections, 400 established and 400 released, threads back to 2 — and running
it revealed the finding that mattered more than its result:

**No workflow ran it.** `grep -rn run-soak .github/workflows/*.yml` returned nothing. The
harness's own header gives the justification for its existence ("a leak per connection is
invisible at 200 connections and fatal at 200,000"), so the property was verified only when
someone remembered, and nothing recorded the outcome. That is `AUD-0018`, filed and fixed in the
same round: a nightly `soak.yml` with manual dispatch, plus the soak in this sweep's heavy set.

A clean sweep two rounds earlier would not have found it, because the sweep runs the gates that
exist and this was the absence of one. That is worth recording next to the convergence claim
rather than buried: convergence means a sweep adds nothing, and the standard's sweeps are not
the only place work comes from.

## Sweep 3 — primary host, after the L5 fix

24 gates, **0 failed**. This is the run that satisfies the standard's convergence condition: the
first sweep after the last discovery, with nothing new found.

## Heavy gates (`SWEEP_HEAVY=1`)

These are in the script but not in the three runs above, because on the primary host they are
serialised against each other by memory rather than by choice. Their status is recorded in
`AUDIT/ledger.json` and the CI workflows, and they are run before Phase E:

- `./Swift/build-release-apple-silicon.sh` — the two-pass reproducible arm64 release build
- the client and server CLI conformance suites (`--scenario all`, 40 scenarios each)
- the peer-input fuzz run under AddressSanitizer
- the package tests under Thread Sanitizer
- `./C99/scripts/build-and-test.sh --sanitize` — the C99 suite under ASan and UBSan
- `./Swift/run-soak.sh` — run on the primary host as the L5 evidence (see above); in this list
  because it is timing-sensitive and belongs on the nightly workflow rather than in front of
  every pull request
