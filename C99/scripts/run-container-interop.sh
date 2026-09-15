#!/bin/sh
# Run the C99 client against a third-party peer, both in containers on ONE Docker network (WT-135).
#
# The host-to-container direction works and the reply path does not: Docker Desktop forwards inbound UDP and the
# container's answers do not return to a host-initiated flow. `check-windows-build.sh`'s sibling in spirit, this
# puts both ends where the network is symmetric, which is also how a Linux CI job would do it.
#
# Usage:  scripts/run-container-interop.sh [peer ...]
#         (no arguments runs every peer this repository knows how to start)
#
# Peers come from the Swift tree's `interop-docker` contexts, because they are the same containers the Swift
# interop matrix uses and there is no reason to write a second one:
#
#   pywebtransport  python:3.12-slim + pywebtransport + aioquic   stream datagram
#   quinn           Rust, quinn + h3                              stream datagram
#   quiche          Rust, quiche (stream only upstream)           stream
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$root/.." && pwd)"
swift_interop="$repo/Swift/interop-docker"

if ! docker info >/dev/null 2>&1; then
  echo "container interop: unsupported -- Docker is not available"
  exit 0
fi

peers="${*:-pywebtransport quinn quiche}"
network="wt-interop-net"
client_image="wt-interop-c99-client"
timeout_ms="${WT_CONTAINER_INTEROP_TIMEOUT_MS:-8000}"
# A check that reports success whatever the client did is not a check: every peer starts at "failed" and only
# the client's own exit status clears it, so the script's status is the interop result rather than a log line.
failures=0

# The client's own gated dumps (C99/docs/DIAGNOSTICS.md). They write INSIDE the container, so the log directory is
# mounted from the host: a diagnostic that dies with the container is a diagnostic nobody reads. Set
# `WT_INTEROP_PACKET_LOG=1` (or SECRET/TRANSCRIPT/STREAM) and the file is printed after the run.
log_dir="$(mktemp -d)"
client_env=""
[ "${WT_INTEROP_PACKET_LOG:-0}" = "1" ] && client_env="$client_env -e WT_QUIC_PACKET_LOG=/logs/packets.log"
[ "${WT_INTEROP_SECRET_LOG:-0}" = "1" ] && client_env="$client_env -e WT_TLS_SECRET_LOG=/logs/secrets.log"
[ "${WT_INTEROP_TRANSCRIPT_LOG:-0}" = "1" ] && client_env="$client_env -e WT_TLS_TRANSCRIPT_LOG=/logs/transcript.log"
[ "${WT_INTEROP_STREAM_LOG:-0}" = "1" ] && client_env="$client_env -e WT_HTTP3_STREAM_LOG=/logs/stream.log"

cleanup() {
  for peer in $peers; do
    docker rm -f "wt-interop-$peer" >/dev/null 2>&1 || true
  done
  docker rm -f wt-interop-client >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$log_dir"
}
trap cleanup EXIT

docker network create "$network" >/dev/null 2>&1 || true

# The client image is built from this tree, so a change to the client is a rebuild rather than a surprise.
docker build -q -t "$client_image" -f "$root/tests/interop/client/Dockerfile" "$root" >/dev/null

for peer in $peers; do
  case "$peer" in
    pywebtransport) port=54001 ;;
    quinn) port=54002 ;;
    quiche) port=54003 ;;
    *) echo "container interop: unknown peer $peer"; exit 2 ;;
  esac
  context="$swift_interop/$peer"
  if [ ! -d "$context" ]; then
    echo "container interop: $peer: no build context at $context"
    failures=$((failures + 1))
    continue
  fi
  echo "== $peer"
  docker build -q -t "wt-interop-$peer" "$context" >/dev/null
  docker rm -f "wt-interop-$peer" >/dev/null 2>&1 || true
  docker run -d --name "wt-interop-$peer" --network "$network" -e "PORT=$port" "wt-interop-$peer" >/dev/null
  sleep 3
  # WT_INTEROP_CAPTURE=1 records the exchange from the peer's own network namespace, which is where a question
  # about packets is answered: it is how the disagreement this round found was seen -- the peer retransmitting its
  # Handshake flight while the client reported the handshake complete.
  if [ "${WT_INTEROP_CAPTURE:-0}" = "1" ]; then
    docker rm -f "wt-capture-$peer" >/dev/null 2>&1 || true
    docker run -d --name "wt-capture-$peer" --network "container:wt-interop-$peer" \
      nicolaka/netshoot tcpdump -n -l -i any -c "${WT_INTEROP_CAPTURE_COUNT:-40}" "udp port $port" >/dev/null 2>&1 || true
    sleep 2
  fi
  # The client JOINS THE PEER'S NETWORK NAMESPACE rather than sitting beside it: `--trust local-development`
  # refuses to bypass certificate verification for a non-loopback address -- which is the right policy, and it
  # said so the first time this ran ("the development bypass is refused for a non-loopback address"). Sharing the
  # namespace makes the peer 127.0.0.1, so the bypass is allowed, no NAT is involved in either direction, and the
  # address on the command line is the loopback one a developer would use anyway.
  # A message is NAMED, because an empty WebTransport stream body carries nothing a peer can observe: `--exchange
  # stream` without `--message` sends the prefix and FIN alone, which is a valid stream and a silent one.
  # The client's exit status IS the result: `|| true` here discarded it and the script always exited 0, so a
  # session that never completed read exactly like one that did.
  # shellcheck disable=SC2086
  if docker run --rm --network "container:wt-interop-$peer" -v "$log_dir:/logs" $client_env "$client_image" \
       --connect "127.0.0.1:$port" --trust local-development --exchange stream \
       --message "${WT_INTEROP_MESSAGE:-hello-interop}" --timeout-ms "$timeout_ms"; then
    echo "container interop: $peer: the client completed the exchange"
  else
    client_status=$?
    echo "container interop: $peer: the client FAILED (exit $client_status)" >&2
    failures=$((failures + 1))
  fi
  for dump in packets secrets transcript stream; do
    if [ -s "$log_dir/$dump.log" ]; then
      echo "-- client $dump log (last 30 lines):"
      tail -30 "$log_dir/$dump.log"
    fi
  done
  if [ "${WT_INTEROP_CAPTURE:-0}" = "1" ]; then
    echo "-- capture (client -> peer, then peer -> client):"
    docker logs "wt-capture-$peer" 2>&1 | grep -E "^[0-9]" | tail -24 || true
    docker rm -f "wt-capture-$peer" >/dev/null 2>&1 || true
  fi
  echo "-- $peer said:"
  docker logs "wt-interop-$peer" 2>&1 | tail -6
  docker rm -f "wt-interop-$peer" >/dev/null 2>&1 || true
done

if [ "$failures" -ne 0 ]; then
  echo "container interop: $failures peer(s) failed (see the client output above)" >&2
  exit 1
fi
echo "container interop: done (every peer's client completed the exchange)"
