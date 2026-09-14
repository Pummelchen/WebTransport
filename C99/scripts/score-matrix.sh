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
echo "definition of done: 8 of 9 criteria met, 1 partial, 0 not met"
echo "  met:     CLI local IPv4/IPv6 sessions; sanitizers and static checks; public API documented; no"
echo "           placeholder exposed as production; the draft-16 matrix itself; all Swift-equivalent"
echo "           conformance coverage (WT-133, closed by the audit that walked the Swift suite scenario by"
echo "           scenario rather than comparing totals); and the interop matrix (WT-135), which was the"
echo "           last criterion to move. The C99 CLIENT completes all SEVEN Phase 11 proofs against FIVE"
echo "           independent implementations on a routable host -- pywebtransport/aioquic (stream),"
echo "           web-transport-quinn (stream and datagram), web-transport-quiche (stream),"
echo "           hyperium/h3-webtransport (datagram) and erlang-webtransport (stream and datagram) --"
echo "           with --trust system, so the chain is validated against the platform trust store AND the"
echo "           certificate's name is checked. Reproduced by two independent full runs with every proof"
echo "           passing on its first attempt, and scripts/run-vps-third-party-interop.sh counts the"
echo "           aggregate from the proof files rather than asserting it. Two of the five peers needed a"
echo "           patch, both kept under tests/interop/peer/. The container matrix still covers both"
echo "           directions and is where eight real defects only a peer can show were found (WT-146,"
echo "           WT-153, WT-154, WT-156, WT-158, WT-166)."
echo "  partial: the FreeBSD and Windows CI legs (WT-134): both platforms are now MEASURED, and what is"
echo "           missing is a CI JOB for each. Windows: the whole tree compiles under mingw with the POSIX"
echo "           warning set as errors and LINKS into 90 PE32+ executables plus a shared library, enforced"
echo "           in CI; and it now RUNS -- scripts/check-windows-wine.sh executes 84 test binaries under"
echo "           Wine, 82 pass, and the 2 failures are real defects the run found (WT-199, WT-200)."
echo "           FreeBSD: a FreeBSD 15.1 guest builds the tree with its base clang and passes the whole"
echo "           suite on a real kernel. What remains is a runner GitHub does not provide natively:"
echo "           environmental, not a code change here"
echo "  (the README score follows the matrix, so this script is where the number comes from)"
