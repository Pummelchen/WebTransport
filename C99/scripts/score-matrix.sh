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
echo "           message exchange against BOTH pywebtransport/aioquic and quinn/web-transport in"
echo "           containers. The quinn investigation found and fixed eight real defects that only a peer"
echo "           can show: max_idle_timeout read as microseconds instead of milliseconds, CRYPTO frames"
echo "           refused in the 1-RTT space, a post-handshake NewSessionTicket failing the handshake, a"
echo "           report that called a killed connection ok, the mandatory SETTINGS_H3_DATAGRAM and every"
echo "           pre-rename version codepoint missing, initial_max_stream_data_bidi_remote missing, a"
echo "           server that sent no control stream and no SETTINGS at all, and -- the one that had kept"
echo "           quinn silent -- the peer's Source Connection ID adopted one pump too late, so the"
echo "           client's Finished went to a connection ID the peer did not know. quiche does not"
echo "           complete the handshake at all (WT-146). The SERVER direction now has a runner too"
echo "           (WT-153): a third-party client completes the handshake with wt-server-c99, its CONNECT"
echo "           is accepted, and its stream bytes then trip the driver (WT-156). That direction has"
echo "           already found the authority comparison and a QPACK value bug (WT-154, fixed and"
echo "           covered by the peer's own field section as a vector). The VPS matrix's five"
echo "           implementations still need a host"
echo "  partial: FreeBSD and Windows CI legs (WT-134)"
echo "  (the README score follows the matrix, so this script is where the number comes from)"
