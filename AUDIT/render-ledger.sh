#!/bin/sh
#
# Renders AUDIT/ledger.md from AUDIT/ledger.json.
#
# The ledger is the single source of truth (§8/§9); this Markdown is generated output
# and must never be edited by hand. Run after every ledger change.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ledger="$root/ledger.json"
out="$root/ledger.md"

[ -f "$ledger" ] || { echo "missing $ledger" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required to render the ledger" >&2; exit 1; }

{
  jq -r '
    "# AUDIT — ledger",
    "",
    "Generated from `AUDIT/ledger.json` by `AUDIT/render-ledger.sh`. Do not edit by hand.",
    "",
    ("Branch `\(.branch)` | primary host \(.primary_host) | baseline `\(.baseline_commit)`"),
    "",
    "## Status counts",
    "",
    ((.tasks | group_by(.status) | map("| \(.[0].status) | \(length) |")) as $rows |
      "| status | count |\n| --- | --- |\n" + ($rows | join("\n"))),
    "",
    ("Non-terminal (open): \(.tasks | map(select(.status != "DONE" and .status != "BLOCKED")) | length)"),
    ("Terminal: \(.tasks | map(select(.status == "DONE" or .status == "BLOCKED")) | length)"),
    "",
    "## Tasks",
    "",
    "| id | severity | tier | project | status | title | file:line |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    (.tasks[] | "| \(.id) | \(.severity) | \(.tier) | \(.project) | \(.status) | \(.title) | \(.file_line) |"),
    "",
    "## Detail",
    "",
    (.tasks[] |
      "### \(.id) — \(.title)",
      "",
      "- severity: \(.severity) | tier: \(.tier) | project: \(.project) | status: \(.status) | host: \(.host)",
      "- category: \(.category) | discovered by: \(.discovered_by)",
      "- where: \(.file_line)",
      "- evidence before: \(.evidence_before)",
      "- fix: \(.fix_summary)",
      "- evidence after: \(.evidence_after)",
      "- commit: \(.commit)",
      (if .blocked_reason != "" then "- BLOCKED: \(.blocked_reason)" else empty end),
      "")
  ' "$ledger"
} > "$out"

echo "rendered $out"
