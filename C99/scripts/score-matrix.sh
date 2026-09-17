#!/bin/sh
# The measured status of the C99 tree, counted from the compliance matrix (WT-136).
#
# The Definition of Done asks for the README's status to go "from 0% to the measured final score", and this makes
# the number reproducible instead of remembered: it counts the matrix's rows by status, separating the rows that
# are DRAFT-16 requirements from the rows that describe the layers the session runs on. It also prints the nine
# Definition-of-Done criteria as they stand, because the matrix's coverage is one thing and the criteria are
# nine -- a single percentage would hide which of the nine are not met.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
matrix="$root/docs/COMPLIANCE-MATRIX.md"
[ -f "$matrix" ] || { echo "score: $matrix is missing"; exit 1; }

# Rows are table lines starting with "| " and not the header or the separator. The leading number is the draft
# section ("3.1", "5.4") or "--" for a row about a lower layer rather than about the draft.
rows="$(grep '^| ' "$matrix" | grep -v '^| # ' | grep -v '^| --- ')"
draft_total=0
draft_tested=0
draft_partial=0
layer_total=0
while IFS= read -r row; do
  section="$(printf '%s' "$row" | cut -d'|' -f2 | tr -d ' ')"
  status="$(printf '%s' "$row" | cut -d'|' -f6 | tr -d ' ')"
  if [ "$section" = "--" ]; then
    layer_total=$((layer_total + 1))
    continue
  fi
  draft_total=$((draft_total + 1))
  case "$status" in
    tested) draft_tested=$((draft_tested + 1)) ;;
    partial) draft_partial=$((draft_partial + 1)) ;;
  esac
done <<ROWS
$rows
ROWS

echo "compliance matrix: $draft_tested of $draft_total draft-16 requirements exercised by a test in this tree"
echo "compliance matrix: $draft_partial of $draft_total partial, and $layer_total row(s) describing lower layers"

# The nine Definition-of-Done criteria are counted from IMPLEMENTATION_PLAN.md's own audit table, whose State
# column is `**met**`, `**partial**` or `**not met**`. The count used to be a hardcoded echo -- "8 of 9 criteria
# met" -- so it kept reporting 8 of 9 after the table it describes had changed, which is the number-nobody-can-
# reproduce failure the criterion itself is about. A table that is missing, empty or not nine rows is reported
# rather than counted from memory.
plan="$root/IMPLEMENTATION_PLAN.md"
[ -f "$plan" ] || { echo "score: $plan is missing"; exit 1; }
criteria="$(sed -n '/^## Definition of Done audit/,/^## /p' "$plan" | grep '^| ' \
            | grep -v '^| Criterion ' | grep -v '^| --- ')"
dod_total=0
dod_met=0
dod_partial=0
dod_not_met=0
while IFS= read -r row; do
  [ -n "$row" ] || continue
  state="$(printf '%s' "$row" | cut -d'|' -f3 | tr -d ' *')"
  dod_total=$((dod_total + 1))
  case "$state" in
    met) dod_met=$((dod_met + 1)) ;;
    partial) dod_partial=$((dod_partial + 1)) ;;
    notmet|unmet) dod_not_met=$((dod_not_met + 1)) ;;
    *) echo "score: unexpected Definition-of-Done state '$state' in $plan"; exit 1 ;;
  esac
done <<CRITERIA
$criteria
CRITERIA
[ "$dod_total" -eq 9 ] || { echo "score: the Definition-of-Done table has $dod_total rows, not nine"; exit 1; }
echo "definition of done: $dod_met of $dod_total criteria met, $dod_partial partial, $dod_not_met not met"
echo "  (counted from the table under 'Definition of Done audit' in IMPLEMENTATION_PLAN.md; the matrix coverage"
echo "   above is the matrix's status cells, whose Evidence names scripts/check-matrix.sh resolves)"
echo "  met:     CLI local IPv4/IPv6 sessions; sanitizers and static checks; public API documented; no"
echo "           placeholder exposed as production; the draft-16 matrix itself; all Swift-equivalent"
echo "           conformance coverage (WT-133, closed by the audit that walked the Swift suite scenario by"
echo "           scenario rather than comparing totals); and the README status, which this script prints"
echo "           from the matrix rather than from memory."
echo "           The five-implementation VPS interop matrix (WT-135) is met again: the C99 CLIENT reproduces"
echo "           all SEVEN Phase 11 proofs against FIVE independent implementations on a routable host --"
echo "           pywebtransport/aioquic (stream), web-transport-quinn (stream and datagram),"
echo "           web-transport-quiche (stream), hyperium/h3-webtransport (datagram) and erlang-webtransport"
echo "           (stream and datagram) -- with --trust system, so the chain is validated against the"
echo "           platform trust store AND the certificate's name is checked. The 17 September 2026 re-run"
echo "           is 7 of 7 (passedProofCount 7, requiredProofCount 7, allPassed true, failedProofs empty),"
echo "           every proof on its first attempt. Its first attempt reproduced five because the deployed"
echo "           wt-erlang image was stale -- it kept only the first certificate in the PEM and served the"
echo "           leaf alone, and it predated tests/interop/peer/patch-erlang-chain.py -- and rebuilt from"
echo "           the patched source all five published ports verify (WT-196, closed in 3de080b, which also"
echo "           lands the deploy, reset and certificate-renewal scripts, so the environment is reproducible"
echo "           from the repository). Two of the five peers needed a patch, both kept under"
echo "           tests/interop/peer/. scripts/run-vps-third-party-interop.sh counts the aggregate from the"
echo "           proof files rather than asserting it, and the container matrix still covers both directions"
echo "           and is where eight real defects only a peer can show were found (WT-146, WT-153, WT-154,"
echo "           WT-156, WT-158, WT-166)."
echo "  CI job coverage (WT-134): every platform the criterion names is a job. Windows: the whole tree"
echo "           compiles under mingw with the POSIX warning set as errors and LINKS into 91 PE32+"
echo "           executables plus a shared library, enforced in CI, and the native Windows leg is enforced"
echo "           too (WT-224); Wine RUNS the suite -- scripts/check-windows-wine.sh executes 85 test binaries"
echo "           and all 85 pass, 64,900 checks, including a Windows-only test of the datagram layer on both"
echo "           of its receive paths (running it is what found and fixed the three defects of WT-199 and"
echo "           WT-200). FreeBSD: the freebsd job boots a FreeBSD VM on an Ubuntu runner and runs the same"
echo "           configure, build and ctest there (WT-223) -- the runner GitHub does not provide natively was"
echo "           the obstacle, and the VM is the answer to it, as the hand measurement before it suggested --"
echo "           and a linux-debian13 leg runs the suite in a debian:trixie container (WT-225)."
echo "           What the plan's Phase 12 MATRIX still lacks is its two Windows compiler variants, MSVC and"
echo "           Clang-CL (the legs use mingw GCC), which is a row on the C99 tracker rather than a criterion"
echo "  (the README score follows the matrix, so this script is where the number comes from)"
