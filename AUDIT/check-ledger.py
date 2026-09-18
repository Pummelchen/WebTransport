#!/usr/bin/env python3
"""Validate AUDIT/ledger.json against §8 of the audit standard.

The ledger is the single source of truth for this audit, which only works if its own shape is
checked: a task with an empty evidence field, a BLOCKED entry with nobody to unblock it, or a
DONE entry whose commit was never recorded is a hole in the record that nothing else would
notice. Everything here is a rule the standard states, not a preference.

Exit status is 0 when the ledger satisfies them, 1 otherwise, with one line per problem.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

LEDGER = Path(__file__).resolve().parent / "ledger.json"

ID_PATTERN = re.compile(r"^AUD-\d{4}$")
OPTION_PATTERN = re.compile(r"\(\d\)")
SEVERITIES = {"S0", "S1", "S2", "S3"}
STATUSES = {"OPEN", "DONE", "BLOCKED"}

# Fields every task must carry whatever its state. `blocked_reason` is deliberately absent:
# it is required only of BLOCKED tasks, and requiring it everywhere would invite filler.
REQUIRED = (
    "id",
    "severity",
    "tier",
    "project",
    "file_line",
    "title",
    "category",
    "status",
    "host",
    "discovered_by",
    "evidence_before",
)

# Fields a task must carry once it is closed. A DONE task with no commit is untraceable: the
# record says it was fixed and cannot say where.
REQUIRED_WHEN_DONE = ("fix_summary", "evidence_after", "commit")


def check(tasks: list[dict]) -> list[str]:
    problems: list[str] = []
    seen: set[str] = set()

    for task in tasks:
        tid = task.get("id") or "<missing id>"

        for field in REQUIRED:
            if not task.get(field):
                problems.append(f"{tid}: required field '{field}' is empty")

        if not ID_PATTERN.match(tid):
            problems.append(f"{tid}: id does not match AUD-nnnn")

        if tid in seen:
            problems.append(f"{tid}: duplicate id")
        seen.add(tid)

        if task.get("severity") not in SEVERITIES:
            problems.append(f"{tid}: severity {task.get('severity')!r} is not one of {sorted(SEVERITIES)}")

        status = task.get("status")
        if status not in STATUSES:
            problems.append(f"{tid}: status {status!r} is not one of {sorted(STATUSES)}")
            continue

        if status == "DONE":
            for field in REQUIRED_WHEN_DONE:
                if not task.get(field):
                    problems.append(f"{tid}: DONE but '{field}' is empty")

        if status == "BLOCKED":
            reason = task.get("blocked_reason") or ""
            if not reason:
                problems.append(f"{tid}: BLOCKED with no blocked_reason")
                continue
            if "owner:" not in reason:
                problems.append(f"{tid}: BLOCKED without a named owner (expected 'owner:' in blocked_reason)")
            if len(OPTION_PATTERN.findall(reason)) < 2:
                problems.append(f"{tid}: BLOCKED with fewer than two options for the owner")

    return problems


def main() -> int:
    try:
        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ledger: {LEDGER} could not be read: {error}", file=sys.stderr)
        return 1

    tasks = ledger.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        print("ledger: no tasks found", file=sys.stderr)
        return 1

    problems = check(tasks)
    if problems:
        for problem in problems:
            print(f"ledger: {problem}")
        print(f"ledger: {len(problems)} problem(s) in {len(tasks)} tasks")
        return 1

    counts: dict[str, int] = {}
    for task in tasks:
        counts[task["status"]] = counts.get(task["status"], 0) + 1
    summary = ", ".join(f"{status} {counts.get(status, 0)}" for status in sorted(STATUSES))
    print(f"ledger: {len(tasks)} tasks valid ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
