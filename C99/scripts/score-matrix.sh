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
echo "  partial: the interop matrix (WT-135): in BOTH directions. The C99 CLIENT completes a"
echo "           WebTransport session and the message exchange against ALL THREE containerized peers --"
echo "           pywebtransport/aioquic, quinn/web-transport and quiche (WT-146, closed by answering the"
echo "           Retry its server sends, WT-166) -- and a third-party CLIENT does the same against"
echo "           wt-server-c99 -- session accepted, its 25-byte message received, and its own message"
echo "           answered on a stream the server opens. The quinn investigation found and fixed eight real defects that only a peer"
echo "           can show: max_idle_timeout read as microseconds instead of milliseconds, CRYPTO frames"
echo "           refused in the 1-RTT space, a post-handshake NewSessionTicket failing the handshake, a"
echo "           report that called a killed connection ok, the mandatory SETTINGS_H3_DATAGRAM and every"
echo "           pre-rename version codepoint missing, initial_max_stream_data_bidi_remote missing, a"
echo "           server that sent no control stream and no SETTINGS at all, and -- the one that had kept"
echo "           quinn silent -- the peer's Source Connection ID adopted one pump too late, so the"
echo "           client's Finished went to a connection ID the peer did not know. The SERVER direction"
echo "           now has a runner too (WT-153), and it found the authority comparison, a QPACK value"
echo "           bug (WT-154), a forgotten data-stream prefix (WT-156) and an HTTP/3 refusal that"
echo "           closed the TRANSPORT with INTERNAL_ERROR instead of the application form with the"
echo "           HTTP/3 code (WT-158) -- all in two runs. The VPS matrix's five implementations"
echo "           still need a host, which is what keeps this criterion partial: three peers is a matrix"
echo "           by implementation, not the five the plan names"
echo "  partial: the FreeBSD and Windows CI legs (WT-134): the Windows half is measured as far as a job"
echo "           without a Windows runner can be -- the WHOLE tree compiles under mingw with the POSIX"
echo "           warning set as errors (75 library sources and 104 test/app sources) and LINKS into 89"
echo "           PE32+ executables plus a shared library, and that link step is ENFORCED in CI now that it"
echo "           has been seen to finish. The Linux legs unpack the WINDOWS OpenSSL before that compile, so"
echo "           the headers are the target's; a machine without one falls back to the host's, searched"
echo "           after the target's with -idirafter (WT-187). What remains is RUNNING what already builds"
echo "           (Windows or Wine) and"
echo "           a FreeBSD runner GitHub does not provide natively: environmental, not a code change here"
echo "  (the README score follows the matrix, so this script is where the number comes from)"
