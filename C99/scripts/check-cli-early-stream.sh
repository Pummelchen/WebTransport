#!/bin/sh
# A client that sends BEFORE its CONNECT, which is the order section 4.6 is about (WT-189).
#
# Draft-16 section 4.6: "clients can, however, send a SETTINGS frame, multiple WebTransport CONNECT requests,
# WebTransport data streams, and WebTransport datagrams all within a single flight. As those can arrive out of
# order, a WebTransport server can receive a stream or a datagram without a corresponding session ... endpoints
# SHOULD buffer streams and datagrams until they can be associated with an established session."
#
# Every other script here drives a well-ordered client, so the SERVER's parking path had no way to be reached
# from the tools at all: the client sent its CONNECT first, the server accepted it in the round it arrived, and
# the window in which a stream can be parked never existed. `--early-stream` opens the CONNECT stream, sends the
# message on a data stream, and only then writes the CONNECT -- so the server receives a WebTransport stream
# naming a session it has not accepted yet, which is exactly the case the section describes.
#
# What the act asserts, and why these are the right assertions:
#
#   - the SERVER reports the message's bytes. They could only arrive through the parking path: the stream names a
#     session the server has not accepted, so the alternative is a refusal, which would leave the message
#     undelivered and this number zero. This is the assertion the act exists for.
#   - the CLIENT reports `earlyStream: true`, so a report says which order the run used rather than leaving the
#     reader to infer it from timing.
#   - the session still comes up (accepted, established, 200 on both sides), because parking must not cost the
#     session: the stream is delivered when the session becomes known, not dropped.
#   - and the flag is a CLIENT's: a listener that passed it would be asking to send before a CONNECT it has not
#     received, so the tool refuses the command line with exit 2 rather than ignoring it.
#
# Both exchange modes are run: a stream and a datagram are parked by the same object but through different paths,
# and the datagram's bound is a drop where the stream's is a rejection.
set -eu

server="$1"
client="$2"
port="${3:-45431}"
mode="${4:-stream}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  echo "cli early stream: $1"
  echo "--- client:"; cat "$work/client.json"
  echo "--- server:"; cat "$work/server.json"
  exit 1
}

"$server" --listen "127.0.0.1:$port" --message pong --exchange "$mode" --timeout-ms 10000 --json \
  >"$work/server.json" 2>&1 &
server_pid=$!
# The server must be listening before the client writes; a short pause is enough for a bound socket, and the
# client retransmits its Initial anyway, which is what a real peer does.
sleep 1
"$client" --connect "127.0.0.1:$port" --origin localhost --exchange "$mode" --message ping \
  --early-stream --timeout-ms 10000 --json >"$work/client.json" 2>&1
wait "$server_pid"

grep -q '"status":"ok"' "$work/client.json" || fail "the client did not report ok"
grep -q '"status":"ok"' "$work/server.json" || fail "the server did not report ok"
grep -q '"earlyStream":true' "$work/client.json" || fail "the client did not report the early order"
grep -q '"established":true' "$work/client.json" || fail "the client was not established"
grep -q '"connectAccepted":true' "$work/client.json" || fail "the client saw no accepted CONNECT"
grep -q '"responseStatus":200' "$work/client.json" || fail "the response was not a 200"
# The point of the act: the server received a message that arrived before the session it named did. Four bytes,
# and the only path that can deliver them is the parking one.
grep -q '"receivedBytes":4' "$work/server.json" \
  || fail "the server did not deliver the early stream's bytes: the stream was refused rather than parked"
grep -q '"receivedBytes":4' "$work/client.json" || fail "the client did not receive the server's message"
grep -q "\"receivedDatagram\":$([ "$mode" = datagram ] && echo true || echo false)" "$work/server.json" \
  || fail "the server's report does not match the $mode mode"
# The reports are JSON, so they are parsed rather than grepped: a field appended without its comma is a report no
# caller could read, and every substring assertion above would pass it (WT-144).
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

# And the flag belongs to the client alone. Exit 2 is the usage status, which is the same one an unsupported
# transport gets: a listener that asked for this would be asking for an order it cannot be in.
set +e
"$server" --listen "127.0.0.1:$port" --early-stream >"$work/refused.out" 2>"$work/refused.err"
status=$?
set -e
[ "$status" -eq 2 ] || fail "--early-stream on a listener must exit 2 (got $status)" "$work/refused.err"

echo "cli early stream ($mode): the server delivered a stream that arrived before its session, and the flag is refused where it means nothing"
