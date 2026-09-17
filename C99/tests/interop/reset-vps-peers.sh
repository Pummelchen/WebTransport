#!/bin/sh
# Restart the interop peer that serves one proof, so a peer with a session ceiling meets it fresh.
#
# This is the in-repository implementation `WEBTRANSPORT_VPS_INTEROP_RESET` names. The runner calls it
# before each proof with the proof key as the argument; the reset matters because
# `erlang-webtransport` serves a bounded number of sessions and then stops accepting, so its datagram
# proof passes alone and fails inside a full run. `deploy-vps-peers.sh` installs this as
# `/usr/local/sbin/webtransport-interop-reset-peers`, and the suite is pointed at it with
#
#   WEBTRANSPORT_VPS_INTEROP_RESET='ssh -o BatchMode=yes root@<host> /usr/local/sbin/webtransport-interop-reset-peers'
#
# Only the long-running `wt-*` set is restarted: those are the five endpoints the C99 suite talks to.
# The internal `wt2-*` set is the Swift matrix's, and restarting it from here would disrupt a run that
# does not belong to this suite.
#
# Usage:  reset-vps-peers.sh [proof-key]     # no key restarts all five
set -eu

key="${1:-}"

case "$key" in
  pywebtransport*) names="wt-py" ;;
  quinn*)          names="wt-quinn" ;;
  quiche*)         names="wt-quiche" ;;
  h3*)             names="wt-h3" ;;
  erlang*)         names="wt-erlang" ;;
  *)               names="wt-py wt-quinn wt-quiche wt-h3 wt-erlang" ;;
esac

command -v docker >/dev/null 2>&1 || { echo "reset-vps-peers: docker is not on PATH"; exit 2; }

restart_one() {
  name="$1"
  # A peer that is not deployed is not an error: the matrix is allowed to run against a subset.
  docker inspect "$name" >/dev/null 2>&1 || return 0
  # `--since` is taken immediately before the restart, so the word this waits for is the NEW
  # listener's, not the previous one's still sitting in the log.
  since="$(date +%s)"
  # The peers ignore SIGTERM; 2s bounds Docker's stop wait instead of its 10s default.
  docker restart -t 2 "$name" >/dev/null
  tries=30
  while [ "$tries" -gt 0 ]; do
    if docker logs --since "$since" "$name" 2>&1 | grep -qi "listening"; then
      echo "reset-vps-peers: $name listening"
      return 0
    fi
    tries=$((tries - 1))
    sleep 1
  done
  echo "reset-vps-peers: $name restarted but did not report a listener within 30s" >&2
  return 1
}

for name in $names; do
  restart_one "$name"
done
