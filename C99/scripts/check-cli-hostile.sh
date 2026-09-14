#!/bin/sh
# The client tool against a peer that BREAKS A RULE (WT-147).
#
# Every other peer this repository can stand up is well behaved, so the tools' refusal path has only ever been
# exercised in one process, by the conformance scenarios that drive both endpoints directly. A caller who runs
# `wt-client-c99` against a hostile peer has no such luxury, and what is under test here is the TOOL: its exit
# status, and whether its report names the rule that was broken.
#
# The act is `max-streams-decrease`: the peer sends a MAX_STREAMS below the limit its own transport parameters
# granted, which RFC 9000 section 4.6 makes a PROTOCOL_VIOLATION (0x0a) naming the frame (0x12). The peer is the
# conformance tool's listening mode, which is also what lets the assertion be made TWICE -- once on the client's
# report ("the code I sent") and once on the peer's ("the code I received"). Those are different claims, and only
# the second one says the refusal reached the wire.
#
# The port is fixed because the client needs the peer's address before the peer can print it; a single test on a
# build machine is not a race, which is the same note the session script carries.
set -eu

conformance="$1"
client="$2"
port="${3:-45427}"
act="${4:-max-streams-decrease}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The reports are PARSED rather than grepped, because a field appended without its comma produced a report no
# caller could read while every substring assertion passed it (`WT-144`). The parser is `python3`, and a machine
# without one -- FreeBSD does not ship it in base, and a Windows environment may not have it -- must say so
# rather than report a broken protocol: a missing interpreter read as `a report is not valid JSON` and turned
# eight working CLI sessions into eight failures on the FreeBSD leg (`WT-201`). 77 is CTest's SKIP_RETURN_CODE,
# which the registration in `apps/CMakeLists.txt` sets for this test, so the skip is visible in a summary instead
# of being counted as a pass.
if ! command -v python3 >/dev/null 2>&1; then
  echo "cli hostile: unsupported -- python3 is not installed, so the JSON reports cannot be parsed (WT-201)"
  exit 77
fi

# What each act must make the client do. The acts differ in the CLOSE the client sends, and one of them also
# differs in what must NOT happen: a datagram for another session must not be counted as received, which is the
# whole reason that act exists (WT-179). Kept here rather than in the script's prose so a new act cannot be added
# without saying what it expects.
case "$act" in
  max-streams-decrease)
    # A transport close (kind 1) carrying PROTOCOL_VIOLATION and the frame that caused it.
    expect_close='"closeKind":1,"closeSentErrorCode":10,"closeSentFrameType":18'
    expect_status='"status":"protocol"'
    expect_more='grep -q "\"receivedDatagram\":false" "$work/client.json" || fail "a refused frame was counted as a message"'
    ;;
  datagram-for-another-session)
    # An APPLICATION close (kind 2) carrying HTTP/3's ID_ERROR, and NO received bytes.
    expect_close='"closeKind":2,"closeSentErrorCode":264,"closeSentFrameType":0'
    expect_status='"status":"state"'
    # Two assertions: the foreign datagram was not counted as a message, and the peer's own payload bytes are
    # NOT echoed into this endpoint's report. The second is the C99 form of the Swift suite's rule that a refusal
    # must not expose what the peer sent (WT-180): a report is this endpoint's account, not a copy of the wire.
    # An `if` rather than `grep && fail`: under `set -e` a failing grep as the last command of an `&&` list ends
    # the script silently, which is exactly how this assertion first "passed" by killing the run.
    expect_more='grep -q "\"receivedBytes\":0" "$work/client.json" || fail "a datagram for another session was delivered"
    if grep -q "not-yours" "$work/client.json"; then fail "the client report echoed the peer payload"; fi'
    ;;
  *)
    echo "cli hostile peer: unknown act $act"
    exit 2
    ;;
esac

"$conformance" --listen "127.0.0.1:$port" --hostile "$act" --json \
  >"$work/peer.json" 2>&1 &
peer_pid=$!

# The peer binds before the client connects; a short pause covers `docker`-free process start-up, and the client
# retransmits its Initial anyway.
sleep 1
client_status=0
"$client" --connect "127.0.0.1:$port" --trust local-development --timeout-ms 5000 --json \
  >"$work/client.json" 2>&1 || client_status=$?
wait "$peer_pid" || true

fail() {
  echo "cli hostile peer: $1"
  echo "--- client (exit $client_status):"; cat "$work/client.json"
  echo "--- peer:"; cat "$work/peer.json"
  exit 1
}

# A tool that exits 0 after its peer broke a transport rule is a tool a script cannot use.
[ "$client_status" -ne 0 ] || fail "the client exited 0 after the peer broke a rule"
# And the refusal, named: a TRANSPORT close (kind 1) carrying PROTOCOL_VIOLATION and the frame that caused it.
grep -q '"established":true' "$work/client.json" || fail "the handshake did not complete, so nothing was refused"
# The tool's own status names the LAYER, not the clock: "protocol" is the refusal, and "timeout" is what this run
# used to say -- for a refusal that had already arrived (WT-147).
grep -q "$expect_status" "$work/client.json" || fail "the client's status does not name the refusal"
grep -q "$expect_close" "$work/client.json" || fail "the client's close is not the one this act requires"
eval "$expect_more"
# The peer's own view: what it sent, and the code it RECEIVED.
grep -q '"sentHostileFrame":true' "$work/peer.json" || fail "the peer did not perform the act"
grep -q '"peerClosed":true' "$work/peer.json" || fail "the peer did not receive a close"
grep -q '"result":"passed"' "$work/peer.json" || fail "the peer did not confirm the refusal"
# The reports are JSON, so they are PARSED rather than grepped: a field appended without its comma produced a
# report no caller could read while every substring assertion above passed it (WT-144).
python3 - "$work/client.json" "$work/peer.json" <<'VALIDATE' || fail "a report is not valid JSON"
import json, sys
for path in sys.argv[1:]:
    with open(path) as handle:
        for number, line in enumerate(handle, 1):
            if line.strip():
                try:
                    json.loads(line)
                except ValueError as error:
                    sys.stderr.write(f"{path}:{number}: {error}\n")
                    sys.exit(1)
VALIDATE

echo "cli hostile peer: the client answered $act with the close this act requires, on both reports"
