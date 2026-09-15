#!/bin/sh
# Run the nested manifest's cross-process library smoke pair (F-repo-ops-16).
#
# `Swift/Package.swift` declares LibrarySmokeServer/LibrarySmokeClient, and until this
# script existed nothing built or ran them: the root manifest does not declare them and no
# workflow, test or script named them. This starts the server on an ephemeral port, waits
# for its readiness line, runs the client's quick path against it, and requires BOTH
# processes to exit zero.
#
# The suite path (`--suite`) is deliberately not run here. It drives several simultaneous
# sessions on one connection, and the library refuses a second session without negotiated
# WebTransport flow control, which the shipped runtime does not advertise (the boundary
# recorded by F-swift-architecture-06), so the suite fails for a reason that belongs to the
# harness rather than to this script's job. This is stated rather than silently omitted.
set -eu

cd "$(dirname "$0")"

server_log="$(mktemp "${TMPDIR:-/tmp}/webtransport-smoke-server.XXXXXX")"
client_log="$(mktemp "${TMPDIR:-/tmp}/webtransport-smoke-client.XXXXXX")"
server_pid=""

cleanup() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -f "$server_log" "$client_log"
}
trap cleanup EXIT INT TERM

swift build --product LibrarySmokeServer --product LibrarySmokeClient

bin_dir="$(swift build --show-bin-path)"
server_binary="$bin_dir/LibrarySmokeServer"
client_binary="$bin_dir/LibrarySmokeClient"
if [ ! -x "$server_binary" ] || [ ! -x "$client_binary" ]; then
    echo "library smoke: the nested manifest's smoke binaries were not built" >&2
    exit 1
fi

# Port 0 asks the kernel for a free port, so two runs (or a busy developer machine) cannot
# collide; the server reports the port it got on its readiness line.
"$server_binary" --port 0 >"$server_log" 2>&1 &
server_pid=$!

port=""
attempt=0
while [ "$attempt" -lt 100 ]; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        break
    fi
    port="$(sed -nE 's/.*listening on 127\.0\.0\.1:([0-9]+).*/\1/p' "$server_log" | head -n 1)"
    [ -n "$port" ] && break
    attempt=$((attempt + 1))
    sleep 0.1
done
if [ -z "$port" ]; then
    echo "library smoke: the server never reported a listening port" >&2
    cat "$server_log" >&2
    exit 1
fi

if ! "$client_binary" --host 127.0.0.1 --port "$port" --quick >"$client_log" 2>&1; then
    echo "library smoke: the client failed" >&2
    cat "$client_log" >&2
    exit 1
fi

# The server completes when the client's final result envelope arrives, so a non-zero exit
# here is a server-side failure and not just shutdown noise.
if ! wait "$server_pid"; then
    echo "library smoke: the server failed" >&2
    cat "$server_log" >&2
    exit 1
fi
server_pid=""

cat "$client_log"
cat "$server_log"
echo "library smoke: the nested manifest's smoke pair completed"
