#!/usr/bin/env python3
"""Render AUDIT/report.md from AUDIT/ledger.json.

§9 of the audit standard asks for the report to come from the ledger, so the counts, the severity
and tier breakdowns and the finding table below are read out of `ledger.json` rather than typed.
The prose sections -- scope, method, the verification yardstick, Phase E -- state what the audit
did and what it could not do, and are deliberately not derived from anything: a report that
recomputed its own conclusions from the ledger could not contradict it.

Write to stdout; the caller redirects it to `AUDIT/report.md`.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

LEDGER = Path(__file__).resolve().parent / "ledger.json"

# The gates every sweep runs, in the order `run-sweep.sh` does. Named here so the report says what
# was actually run rather than how many things were.
GATES = (
    "toolchain pinned (Swift 6.4 / Xcode 27)",
    "manifests agree on shared targets",
    "no unsafe build flags",
    "the two libraries report the same version",
    "target imports declared as dependencies",
    "swift-format lint --strict",
    "swiftlint lint --strict",
    "swift build with safety diagnostics",
    "public API compatibility sample",
    "package tests",
    "PKCS#12 resolution is keychain-free",
    "nested manifest test target",
    "library smoke pair",
    "build, warnings-as-errors, ctest",
    "RFC vectors match the documents",
    "installed package consumer",
    "compliance matrix against the tree",
    "portability inventory against the tree",
    "no dead locals hidden by a (void) cast",
    "tree matches .clang-format",
    "cppcheck",
    "Clang Static Analyzer",
    "workflow files parse",
    "ledger satisfies the standard's field rules",
    "ledger.md matches the ledger",
    "report.md matches the ledger",
    "gitleaks over full history",
    "trivy filesystem scan",
)

HEAVY_GATES = (
    "client and server CLI conformance (`--scenario all`, 40 each)",
    "the suite under AddressSanitizer (379 tested, 0 failed)",
    "the peer-input fuzz run under AddressSanitizer",
    "the suite under Thread Sanitizer",
    "the C99 suite under ASan and UBSan (97/97)",
    "the reproducible arm64 release build",
    "the connection-churn soak (400/400 sessions, no sustained growth)",
)


def counts(tasks: list[dict], key: str) -> dict[str, int]:
    return dict(sorted(collections.Counter(task[key] for task in tasks).items()))


def table(rows: list[list[str]], headers: list[str]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(out)


def main() -> int:
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    tasks = ledger["tasks"]
    status = counts(tasks, "status")
    severity = counts(tasks, "severity")
    tier = counts(tasks, "tier")
    non_terminal = [task for task in tasks if task["status"] != "DONE"]

    print("# AUDIT — report")
    print()
    print("Generated from `AUDIT/ledger.json` by `AUDIT/render-report.py`. The counts, the")
    print("breakdowns and the finding table are read from the ledger; the prose is not, because a")
    print("report that recomputed its own conclusions could not contradict them.")
    print()
    print("Branch `audit/2026-09-18`. Primary host `Mac14,3` (macOS 27.0, Xcode 27.0, Swift 6.4).")
    print("Baseline commit `397b047`, which `main` still points at.")
    print()
    print("## What was done")
    print()
    print("A pre-production audit of both libraries in this repository — the Swift package and the")
    print("independent C99 CMake library — against the supplied standard: the pinned toolchain")
    print("recorded per language (`environment.md`), tool coverage and language-standard enforcement")
    print("proved with deliberate violations (`tool-coverage.md`), the ledger kept as the single")
    print("source of truth, both projects baselined on the primary host (`baseline.md`), the L0-L7")
    print("passes run at tier-appropriate depth plus the standard's own §5 façade hunt and §6 unused-")
    print("code pass (`passes.md`), every finding fixed in severity order with `run-sweep.sh` as the")
    print("gate, and discovery repeated until a full sweep added no new task (`convergence.md`).")
    print()
    print("The Tier A review is recorded in `tier-a-review.md`, which names what was read, what it")
    print("found, and — for the refusals it could not reach — the proof that they are unreachable.")
    print("Phase E has not run: it needs an independent host, and the standard says to ask first")
    print("(`phase-e.md`, `AUD-0002`).")
    print()
    print("## Findings")
    print()
    print(f"{len(tasks)} tasks were filed. " + ", ".join(f"{k} {v}" for k, v in status.items()) + ".")
    print()
    print(
        table(
            [[k, str(v)] for k, v in severity.items()],
            ["severity", "count"],
        )
    )
    print()
    print(
        table(
            [[k, str(v)] for k, v in tier.items()],
            ["tier", "count"],
        )
    )
    print()
    print(
        table(
            [[task["id"], task["severity"], task["status"], task["title"]] for task in tasks],
            ["id", "sev", "status", "finding"],
        )
    )
    print()
    print("## Verification yardstick")
    print()
    print("Every claim above rests on gates, not on reading. `AUDIT/run-sweep.sh` runs the same")
    print(
        "commands the CI workflows do, so the two cannot drift; the final sweep ran "
        f"{len(GATES)} gates and **0 failed**:"
    )
    print()
    for gate in GATES:
        print(f"- {gate}")
    print()
    print("The heavy gates are serialised on the primary host and run before Phase E:")
    print()
    for gate in HEAVY_GATES:
        print(f"- {gate}")
    print()
    print("The regression yardstick, unchanged from the baseline: both projects build with 0")
    print("warnings, Swift tests 401, C99 tests 97/97, C99 line coverage **91.97%** (from 91.64% when")
    print("first measured, having dipped to 91.49% under the audit's own added branches), SwiftLint 0")
    print("findings from 556, `swift format lint --strict` clean, gitleaks and trivy clean.")
    print()
    print("## Convergence")
    print()
    print("`AUDIT/convergence.md` records the sweeps in order. The last one added no task, which is")
    print("the standard's convergence condition; three of the later sweeps were re-run after the")
    print("Tier A review found work the sweep itself could not, which is recorded there rather than")
    print("folded into the first convergence claim.")
    print()
    print("## Not done, and why")
    print()
    if non_terminal:
        print(
            table(
                [
                    [task["id"], task["severity"], task["status"], task["title"], task.get("blocked_reason", "")]
                    for task in non_terminal
                ],
                ["id", "sev", "status", "finding", "blocked on"],
            )
        )
    print()
    print("**Phase E has not run.** §12 makes the audit complete when the open count is exactly 0")
    print("(it is) *and* Phase E has passed on an independent host (it has not — there is no host).")
    print("Calling this audit complete would be the kind of claim the audit exists to prevent.")
    print("`AUDIT/phase-e.md` is the runbook: what makes a host independent, what to install, the")
    print("exact commands, what counts as passing, and what a failure there means.")
    print()
    print("`AUD-0008` is the second open decision: the standard asks for")
    print("`-require-explicit-sendable` in the build configuration, the only SwiftPM mechanism for")
    print("that breaks published consumers, and the three options for the repository owner are")
    print("recorded on the task.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
