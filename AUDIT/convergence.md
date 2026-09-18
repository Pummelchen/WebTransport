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

## Between sweeps 3 and 4: the §5 facade hunt added a task

The L0–L7 passes are not the whole standard; §5 (facade hunt) and §6 (unused code) are their own
passes and they had not been run. Running them found `AUD-0019`: `check-portability.sh` ended
with "every POSIX-only name the library uses is in the inventory", but it can only check the
names on its own hand-maintained list. Injecting `getpid()` -- a POSIX call MSVC does not have
-- left it green and printing that sentence.

Widening the list then found two calls the library really uses and the inventory did not name
(`htons`, `clock_gettime`), and the document's own description of the check was stale ("The two
symbols this document is checked for", listing nine, while the script checked nineteen). All
three are fixed, and the mechanism's limit is now written down in both places with the real
enforcement named -- the Windows jobs, verified to build the library rather than only configure
it. Details in `AUDIT/passes.md`.

The same lesson as AUD-0018 with a different instrument: a clean sweep is not the same thing as
a complete audit, and the standard's passes find what the sweep cannot.

## Sweep 4 — primary host, after the §5/§6 passes

24 gates, **0 failed**. The first sweep after the last discovery, which is again the standard's
convergence condition.

## Sweep 5 — primary host, after the §7–§10 process review

25 gates, **0 failed**. The sweep grew by one: `AUDIT/check-ledger.py` now validates the
ledger's own shape (§8) — required fields, unique well-formed ids, allowed severities and
statuses, a fix/evidence/commit on every `DONE` task, and a named owner plus at least two
options on every `BLOCKED` one. It was written because that check found eleven `DONE` tasks with
no commit recorded.

The process rules themselves are reviewed in `AUDIT/compliance.md`, including the two places
they were not followed.

## Sweep 6 — primary host, after the sanitizer-coverage fix

25 gates, **0 failed**. The heavy set grew: it now runs the whole Swift suite under
AddressSanitizer rather than the three-test fuzz filter, which is what AUD-0020 found and fixed.

## Sweep 7 — primary host, after the dead-local fix

26 gates, **0 failed**. The new gate is `C99/scripts/check-unused-locals.py` (AUD-0021).

## Sweep 8 — primary host, after the NEW_TOKEN fix

26 gates, **0 failed**.

## Sweep 9 — primary host, after the version-negotiation fix

26 gates, **0 failed**.

## Sweep 10 — primary host, after pinning the version-negotiation answers

26 gates, **0 failed**. Test-only change: the three long-header walkers' answers for a Version
Negotiation packet are now all asserted, and both guards that refuse were proved by deliberate
violation.

## Sweep 11 — primary host, after the ACK-validator tests

26 gates, **0 failed**.

## Sweep 12 — primary host, after the capsule refusal tests

26 gates, **0 failed**.

## Sweep 13 — primary host, after the QPACK prefix refusal tests

26 gates, **0 failed**.

## Sweep 14 — primary host, after the QPACK capacity refusal

26 gates, **0 failed**.

## Sweep 15 — primary host, after the ClientHello cipher-suite test

26 gates, **0 failed**.

## Sweep 16 — primary host, after the initial-token guard tests

26 gates, **0 failed**.

## Sweep 17 — primary host, after the trust-mode refusal tests

26 gates, **0 failed**.

## Sweep 18 — primary host, after the unreachability verdicts

26 gates, **0 failed**.

## Sweep 19 — primary host, after the capsule refusal tests

26 gates, **0 failed**.

## Sweep 20 — primary host, after the section 7.3 client-half tests

26 gates, **0 failed**.

## Sweep 21 — primary host, after the Huffman proof and the empty-method test

26 gates, **0 failed**.

## Sweep 22 — primary host, after the framing proof and the protocol token test

26 gates, **0 failed**.

## Sweep 23 — primary host, after the trailer-rule test was made real

26 gates, **0 failed**.

## Sweep 24 — primary host, after the static-index boundary tests

26 gates, **0 failed**.

## Heavy gates — primary host, run before Phase E

Six gates, **6 passed**. They are kept out of the per-round sweep because on the primary host
(8 GB) they are serialised against each other by memory rather than by choice -- `SWEEP_HEAVY=1`
runs them, and their results are below. Each was checked by reading its log, not by its exit
code alone, because a gate that returns zero without doing its work is the failure mode this
whole exercise is about:

| Gate | Result | Evidence |
| --- | --- | --- |
| `WebTransportClient --scenario all` | PASS | `passed=40 failed=0 skipped=0 total=40` -- all forty, both Release scenarios included because it ran from the repository root |
| `WebTransportServer --scenario all` | PASS | `passed=40 failed=0 skipped=0 total=40` |
| `C99/scripts/build-and-test.sh --sanitize` | PASS | `100% tests passed out of 97` under AddressSanitizer and UndefinedBehaviorSanitizer (51 s) |
| `swift test --sanitize=address --filter 'peerFacingParsers\|huffmanDecoder'` | PASS | 3 tests, including `peerFacingParsersNeverTrapOnArbitraryInput` |
| `swift test --sanitize=address --skip CLIProcess --skip ReleaseArtifacts` | PASS | **the whole suite** under ASan: 379 passed, 0 failed, no sanitizer reports (added by AUD-0020) |
| `swift test --sanitize=thread --skip CLIProcess --skip ReleaseArtifacts` | PASS | 0 failures under Thread Sanitizer |
| `./Swift/build-release-apple-silicon.sh` | PASS | `Release artifacts are reproducible` with per-binary checksums; both are `Mach-O 64-bit executable arm64` |

One of them nearly read as a false alarm and is worth recording: the Thread Sanitizer log
contains "Failed" in the *name* of a passing test
(`udpPortReportsAFailedSetsockoptUnderItsOwnOperation`), so a `grep -i failed` over the logs
flags a green run. The logs were read rather than grepped for a verdict.

`./Swift/run-soak.sh` is the seventh heavy gate; it was run as the L5 evidence (see between
sweeps 2 and 3 above) and is in the nightly `soak.yml` from AUD-0018.
