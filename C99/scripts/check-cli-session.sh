#!/bin/sh
# The two CLI tools, against each other, over a real socket (Phase 9).
#
# The conformance tool drives both endpoints in one process, which proves the library path; this proves the
# TOOLS' path: `wt-server-c99 --listen` in one process and `wt-client-c99 --connect` in another, each with its
# own command line, its own sockets and its own JSON report. It is registered with CTest, so "the CLI tools run
# local packet sessions" is checked on every build rather than demonstrated by hand.
#
# The port is fixed because the server's report is written when it FINISHES, so the client cannot learn a
# chosen port from it in time. A single test on a build machine is not a race; a suite that ran several of these
# at once would need the port passed through a file, and that is the note for whoever adds the second one.
set -eu

server="$1"
client="$2"
port="${3:-45417}"
mode="${4:-stream}"
host="${5:-127.0.0.1}"
conformance="${6:-}"
# A seventh argument makes the SERVER validate the client's address with a Retry before serving it (WT-168): the
# client tool has to answer the Retry and adopt the connection ID it named, which is a code path no other case
# here reaches.
retry="${7:-}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# An IPv6 run needs an IPv6 loopback, and a machine without one is a fact about the machine: the conformance
# tool's own IPv6 scenario is the probe, and 77 is CTest's SKIP_RETURN_CODE rather than a failure of this code.
if [ "${host#\[}" != "$host" ] && [ -n "$conformance" ]; then
  if ! "$conformance" --scenario all --json 2>/dev/null | grep -q '"name":"session-over-ipv6","result":"passed"'; then
    echo "cli session ($mode): no IPv6 loopback on this machine, skipped"
    exit 77
  fi
fi

"$server" --listen "$host:$port" --message pong --exchange "$mode" --timeout-ms 10000 --json ${retry:+--retry} \
  >"$work/server.json" 2>&1 &
server_pid=$!

# The server must be listening before the client writes; a short pause is enough for a bound socket, and the
# client retransmits its Initial anyway, which is what a real peer does.
sleep 1
"$client" --connect "$host:$port" --origin localhost --exchange "$mode" --message ping \
  --timeout-ms 10000 --json >"$work/client.json" 2>&1

wait "$server_pid"

fail() {
  echo "cli session: $1"
  echo "--- client:"; cat "$work/client.json"
  echo "--- server:"; cat "$work/server.json"
  exit 1
}

grep -q '"status":"ok"' "$work/client.json" || fail "the client did not report ok"
grep -q '"status":"ok"' "$work/server.json" || fail "the server did not report ok"
grep -q '"established":true' "$work/client.json" || fail "the client was not established"
grep -q '"established":true' "$work/server.json" || fail "the server was not established"
grep -q '"connectAccepted":true' "$work/client.json" || fail "the client saw no accepted CONNECT"
grep -q '"responseStatus":200' "$work/client.json" || fail "the response was not a 200"
# And WHY it became a session (WT-155). `responseOutcome` must be the decided value rather than its default:
# 0 means "no response was decoded", and a report that says the session came up while its own outcome says
# nothing arrived is the kind of field-appended-and-never-wired defect this check exists to catch.
grep -q '"responseOutcome":1' "$work/client.json" || fail "the client did not report an accepted response"
grep -q '"h3Error":0' "$work/client.json" || fail "the client reported an HTTP/3 error on a good response"
# Each side received the other's four-byte message, which is the exchange the tools exist to make.
grep -q '"receivedBytes":4' "$work/client.json" || fail "the client did not receive the message"
grep -q '"receivedBytes":4' "$work/server.json" || fail "the server did not receive the message"
# The MODE is asserted too: `--exchange stream` and `--exchange datagram` are different code paths, and a report
# that claimed the same thing for both would be worth nothing.
grep -q "\"receivedDatagram\":$([ "$mode" = datagram ] && echo true || echo false)" "$work/client.json" \
  || fail "the client's report does not match the $mode mode"
grep -q "\"receivedDatagram\":$([ "$mode" = datagram ] && echo true || echo false)" "$work/server.json" \
  || fail "the server's report does not match the $mode mode"
# The reports are JSON, so they are PARSED rather than grepped: a field appended without its comma produced
# `"pin":"..."closeKind":0` -- a report no caller could read -- and every substring assertion here passed it
# (WT-144). One parser run on each line is the check that cannot be fooled that way.
python3 - "$work/client.json" "$work/server.json" <<'VALIDATE' || fail "a report is not valid JSON"
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
# And neither end may claim to have closed a connection it did not close: a report that says `ok` while its own
# close says otherwise is the defect WT-144 fixed, and the reverse -- a false close on a healthy session -- is how
# that fix would break the tools instead. The close is read from the connection's close STATE, so this also says
# the field is wired to the peer's own CONNECT stream rather than defaulted.
grep -q '"closeKind":0,"closeSentErrorCode":0,"closeSentFrameType":0,"closeCause":"ok","closeSent":false' "$work/client.json" \
  || fail "the client claims a close it did not send"
grep -q '"closeKind":0,"closeSentErrorCode":0,"closeSentFrameType":0,"closeCause":"ok","closeSent":false' "$work/server.json" \
  || fail "the server claims a close it did not send"
if [ -n "$retry" ]; then
  # The server's report says the flag was in force, and the client's says the session completed anyway: a Retry
  # that the client ignored would leave no session at all, which the assertions above already refuse.
  grep -q '"retry":true' "$work/server.json" || fail "the server did not report the Retry policy"
  echo "cli session ($mode): the client's address was validated with a Retry before the session over $host:$port"
else
  echo "cli session ($mode): client and server exchanged a WebTransport session over $host:$port"
fi
