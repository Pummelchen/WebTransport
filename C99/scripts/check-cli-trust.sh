#!/bin/sh
# `--trust system` must actually be honoured (WT-193).
#
# The client's trust DEFAULT is `system`, and the session loop used to ignore the option entirely: whatever
# `--trust` said, the client took the loopback development bypass. The JSON report still said
# `"trust":"system"`, so a caller who asked for certificate verification was told they had it and did not.
#
# This proves the option changes what happens, against a self-signed loopback peer where the two modes must
# disagree:
#
#   --trust local-development  the bypass, which the trust layer allows for a loopback name: it establishes
#   --trust system             the platform store, which cannot validate a self-signed leaf: it does NOT
#
# A run that established under both would mean the option is still wired to nothing -- exactly the defect. Each
# attempt gets its OWN server, because a peer that serves one session and exits would make the second attempt
# fail for want of a listener, which is indistinguishable from the refusal being asserted here.
set -eu

server="$1"
client="$2"
port_bypass="${3:-45441}"
port_system="${4:-45443}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pids=""
cleanup() {
  for pid in $pids; do kill "$pid" 2>/dev/null || true; done
}
trap 'cleanup; rm -rf "$work"' EXIT

start_server() {
  port="$1"
  "$server" --listen "127.0.0.1:$port" --message pong --exchange stream --timeout-ms 10000 --json \
    >"$work/server-$port.json" 2>&1 &
  pids="$pids $!"
}

fail() {
  echo "cli trust: $1"
  for log in "$work"/*.json; do
    echo "--- $(basename "$log")"; cat "$log"
  done
  exit 1
}

# 1. The bypass is honoured: a self-signed loopback peer establishes.
start_server "$port_bypass"
sleep 1
"$client" --connect "127.0.0.1:$port_bypass" --trust local-development --origin localhost --exchange stream \
  --message ping --timeout-ms 10000 --json >"$work/bypass.json" 2>&1 || true
grep -q '"established":true' "$work/bypass.json" \
  || fail "the development bypass did not establish a session against a loopback peer"

# 2. System trust must REFUSE the same kind of peer: the leaf is self-signed, so no platform store validates it.
start_server "$port_system"
sleep 1
"$client" --connect "127.0.0.1:$port_system" --trust system --origin localhost --exchange stream \
  --message ping --timeout-ms 10000 --json >"$work/system.json" 2>&1 || true
if grep -q '"established":true' "$work/system.json"; then
  fail "--trust system established a session against a self-signed peer, so the option is not honoured"
fi

# 3. And the report says which mode was asked for, so a reader can tell the two runs apart.
grep -q '"trust":"system"' "$work/system.json" || fail "the system-trust run did not report its mode"
grep -q '"trust":"local-development"' "$work/bypass.json" || fail "the bypass run did not report its mode"

echo "cli trust: local-development establishes and system refuses a self-signed leaf"
