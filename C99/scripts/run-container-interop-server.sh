#!/bin/sh
# Run a third-party WebTransport CLIENT against this tree's server (WT-153).
#
# `run-container-interop.sh` drives this tree's client against somebody else's server, and that direction found seven
# real defects. This is the mirror, and it exists because the server direction had NO runner at all: every
# server-side defect -- including a server that accepted only its own connection ID, and would therefore have
# refused every client that chose its own -- was found by reading code rather than by talking to a peer.
#
# The shape is the same and for the same reason: both ends in containers on one network, and the peer joins the
# C99 server's own network namespace so that the server is 127.0.0.1 and the development trust bypass applies.
#
# Usage:  scripts/run-container-interop-server.sh [peer ...]
#         (no arguments runs every peer client this repository knows how to start)
#
#   pywebtransport  python:3.12-slim + pywebtransport + aioquic   (a WebTransport client)
#
# It EXITS NON-ZERO when a peer does not complete a session, unlike the client-side runner: this one exists to
# prove the server, so a run that only prints is a run nobody will notice failing. It is deliberately NOT a CTest
# entry -- Docker is not a test dependency -- and it is run by hand as part of the interop work.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$root/.." && pwd)"

if ! docker info >/dev/null 2>&1; then
  echo "server interop: unsupported -- Docker is not available"
  exit 0
fi

peers="${*:-pywebtransport}"
failures=0
network="wt-server-interop-net"
server_image="wt-interop-c99-client"
timeout_ms="${WT_SERVER_INTEROP_TIMEOUT_MS:-8000}"
port="${WT_SERVER_INTEROP_PORT:-54070}"
message="pong-from-c99"

cleanup() {
  docker rm -f wt-server-under-test >/dev/null 2>&1 || true
  for peer in $peers; do
    docker rm -f "wt-server-peer-$peer" >/dev/null 2>&1 || true
  done
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$network" >/dev/null 2>&1 || true
docker build -q -t "$server_image" -f "$root/tests/interop/client/Dockerfile" "$root" >/dev/null

for peer in $peers; do
  case "$peer" in
    pywebtransport)
      peer_image="wt-interop-pywebtransport"
      context="$repo/Swift/interop-docker/pywebtransport"
      ;;
    *) echo "server interop: unknown peer $peer"; exit 2 ;;
  esac
  if [ ! -d "$context" ]; then
    echo "server interop: $peer: no build context at $context"
    continue
  fi
  echo "== $peer -> wt-server-c99"
  docker build -q -t "$peer_image" "$context" >/dev/null
  docker rm -f wt-server-under-test >/dev/null 2>&1 || true
  # The server under test, with a message of its own so that BOTH directions are exercised: the peer learns the
  # session is up from the response, and this is what it should receive on a stream the server opens.
  # `--origin localhost` because that is the authority the peer SENDS: pywebtransport/aioquic derives `:authority`
  # from its configured server name ("localhost") rather than from the host in the URL, which is why the request the
  # server reports reads `CONNECT webtransport localhost /` even though the client connected to 127.0.0.1.
  # The server's window has to outlast the peer's start-up, and the readiness wait cannot be a log line: a
  # container's stdout is block-buffered when it is not a TTY, so the reports only appear when the process EXITS
  # -- which the first version of this script mistook for "not bound yet", waited ten seconds for, and then found
  # the server gone. The listener's own peek loop is the wait, so the server gets a longer window and the peer
  # starts after a short pause that only has to cover `docker run`.
  server_timeout_ms=$((timeout_ms * 4))
  # WT_SERVER_RETRY makes the server validate the peer's address with a Retry before serving it (WT-168). The
  # peers here answer a Retry only if they implement RFC 9000 section 8.1.2, which is exactly what this proves.
  retry_flag=""
  if [ -n "${WT_SERVER_RETRY:-}" ]; then
    retry_flag="--retry"
  fi
  docker run -d --name wt-server-under-test --network "$network" \
    -e "WT_HTTP3_SECTION_LOG=${WT_SERVER_SECTION_LOG:-/dev/null}" \
    --entrypoint /build/apps/wt-server-c99 "$server_image" \
    --listen "0.0.0.0:$port" --origin localhost --message "$message" --exchange stream \
    --timeout-ms "$server_timeout_ms" --json $retry_flag >/dev/null
  sleep 2
  # The peer joins the SERVER's namespace: the server is then 127.0.0.1 for the client, which is what the
  # self-signed identity and the development trust path expect, and no NAT is involved in either direction.
  status=0
  docker run --rm --network "container:wt-server-under-test" \
    -v "$root/tests/interop/peer/c99_server_client.py:/srv/c99_server_client.py:ro" \
    --entrypoint python "$peer_image" /srv/c99_server_client.py \
    --host 127.0.0.1 --port "$port" --message "hello-from-$peer" --timeout 8 || status=$?
  # The server serves ONE session and returns, so waiting for it to exit is also how the run is known to be over.
  # Its report is read afterwards, because that is when a buffered stdout reaches `docker logs`.
  waited=0
  while [ "$waited" -lt 60 ]; do
    if [ -z "$(docker ps -q -f name=wt-server-under-test)" ]; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "-- $peer said the above; wt-server-c99 said:"
  docker logs wt-server-under-test 2>&1 | tail -3
  # The server must have seen a session AND the peer's message: a client that "connected" to a server which
  # discarded its packets would otherwise look like a success on one side only.
  if ! docker logs wt-server-under-test 2>&1 | grep -q '"connectAccepted":true'; then
    echo "server interop: $peer: wt-server-c99 did not accept the session"
    status=1
  fi
  if ! docker logs wt-server-under-test 2>&1 | grep -q "\"receivedBytes\":$(printf '%s' "hello-from-$peer" | wc -c | tr -d ' ')"; then
    echo "server interop: $peer: wt-server-c99 did not receive the peer's message"
    status=1
  fi
  if [ "$status" -ne 0 ]; then
    echo "server interop: $peer: FAILED -- see the peer's report and wt-server-c99's own above"
    failures=$((failures + 1))
  else
    echo "server interop: $peer: a third-party client completed a session with wt-server-c99"
  fi
  docker rm -f wt-server-under-test >/dev/null 2>&1 || true
done

echo "server interop: done ($failures peer(s) did not complete a session)"
[ "$failures" -eq 0 ]
