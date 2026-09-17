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
echo "  partial: the five-implementation VPS interop matrix (WT-135): the C99 CLIENT reproduces FIVE of"
echo "           the SEVEN Phase 11 proofs against FIVE independent implementations on a routable host --"
echo "           pywebtransport/aioquic (stream), web-transport-quinn (stream and datagram),"
echo "           web-transport-quiche (stream) and hyperium/h3-webtransport (datagram) -- with --trust"
echo "           system, so the chain is validated against the platform trust store AND the certificate's"
echo "           name is checked. The two erlang-webtransport proofs (stream and datagram) fail"
echo "           status=trust while the other four peers accept the same certificate files, and an RSA"
echo "           certificate tried on the theory that the peer needed one made the other four fail, which"
echo "           excludes key type and leaves that peer's own TLS handling (WT-196). An earlier full run"
echo "           reported 7 of 7; that is not reproducible until WT-196 is fixed. Two of the five peers"
echo "           needed a patch, both kept under tests/interop/peer/. scripts/run-vps-third-party-interop.sh"
echo "           counts the aggregate from the proof files rather than asserting it, and the container"
echo "           matrix still covers both directions and is where eight real defects only a peer can show"
echo "           were found (WT-146, WT-153, WT-154, WT-156, WT-158, WT-166)."
echo "           The FreeBSD CI leg (WT-223) and the plan's MSVC and Clang-CL Windows variants: both platforms"
echo "           are MEASURED, and what is missing is a CI JOB for the FreeBSD one. Windows: the whole tree compiles under mingw with the POSIX"
echo "           warning set as errors and LINKS into 91 PE32+ executables plus a shared library, enforced"
echo "           in CI -- the native Windows leg is enforced too (WT-224), and a linux-debian13 leg runs the"
echo "           suite in a debian:trixie container (WT-225); and Wine RUNS -- scripts/check-windows-wine.sh executes 85 test binaries under"
echo "           Wine and all 85 pass, 64,900 checks, including a Windows-only test of the datagram layer"
echo "           on both of its receive paths. Running it is also what found and fixed the three defects"
echo "           of WT-199 and WT-200 (a receive that mis-reported truncation and dropped the sender, the"
echo "           Retry path that depended on it, and a hand-written WSARecvMsg prototype with one"
echo "           parameter too many that no cross-compile could see)."
echo "           FreeBSD: a FreeBSD 15.1 guest builds the tree with its base clang and passes the whole"
echo "           suite on a real kernel. What remains is a runner GitHub does not provide natively (WT-223):"
echo "           environmental, not a code change here"
echo "  (the README score follows the matrix, so this script is where the number comes from)"
