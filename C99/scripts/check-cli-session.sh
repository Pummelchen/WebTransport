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
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$server" --listen "127.0.0.1:$port" --message pong --timeout-ms 10000 --json >"$work/server.json" 2>&1 &
server_pid=$!

# The server must be listening before the client writes; a short pause is enough for a bound socket, and the
# client retransmits its Initial anyway, which is what a real peer does.
sleep 1
"$client" --connect "127.0.0.1:$port" --origin localhost --exchange stream --message ping \
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
# Each side received the other's four-byte message, which is the exchange the tools exist to make.
grep -q '"receivedBytes":4' "$work/client.json" || fail "the client did not receive the message"
grep -q '"receivedBytes":4' "$work/server.json" || fail "the server did not receive the message"
echo "cli session: client and server exchanged a WebTransport session over 127.0.0.1:$port"
