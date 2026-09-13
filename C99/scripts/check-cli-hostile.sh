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
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$conformance" --listen "127.0.0.1:$port" --hostile max-streams-decrease --json \
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
grep -q '"status":"protocol"' "$work/client.json" || fail "the client did not report a protocol failure"
grep -q '"closeKind":1,"closeSentErrorCode":10,"closeSentFrameType":18' "$work/client.json" \
  || fail "the client did not send a transport close naming PROTOCOL_VIOLATION and MAX_STREAMS"
# The peer's own view: what it sent, and the code it RECEIVED.
grep -q '"sentHostileFrame":true' "$work/peer.json" || fail "the peer did not perform the act"
grep -q '"peerClosed":true,"peerErrorCode":10,"peerCloseFrameType":18' "$work/peer.json" \
  || fail "the peer did not receive the refusal it asked for"
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

echo "cli hostile peer: the client refused a decreasing MAX_STREAMS with 0xa naming frame 0x12, on both reports"
