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
echo "definition of done: 7 of 9 criteria met, 2 partial, 0 not met"
echo "  met:     CLI local IPv4/IPv6 sessions; sanitizers and static checks; public API documented; no"
echo "           placeholder exposed as production; the draft-16 matrix itself; all Swift-equivalent"
echo "           conformance coverage (WT-133, closed by the audit that walked the Swift suite scenario by"
echo "           scenario rather than comparing totals)"
echo "  partial: the interop matrix (WT-135): the C99 client completes a WebTransport session AND the"
echo "           message exchange against pywebtransport/aioquic in a container. Of the three peers this"
echo "           tree can start, one is end to end. quinn's handshake now completes fully and the"
echo "           connection stays alive -- 179 packets seen, its application packets acknowledged -- but"
echo "           the CONNECT is still unanswered (WT-145), and that investigation has already found and"
echo "           fixed four real defects: the peer's max_idle_timeout read as microseconds instead of"
echo "           milliseconds, CRYPTO frames refused in the 1-RTT space, a post-handshake NewSessionTicket"
echo "           failing the handshake, and a report that called a killed connection ok. quiche does not"
echo "           complete the handshake at all (WT-146). The VPS matrix's five implementations still need"
echo "           a host"
echo "  partial: FreeBSD and Windows CI legs (WT-134)"
echo "  (the README score follows the matrix, so this script is where the number comes from)"
