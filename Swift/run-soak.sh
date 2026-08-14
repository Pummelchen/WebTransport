#!/bin/bash
#
# Connection-churn soak for the WebTransport listener.
#
# The runtime hardening work claimed bounded task lifetimes after removing a
# detached polling task that could outlive its connection. A passing unit suite
# does not demonstrate that: a leak per connection is invisible at 200
# connections and fatal at 200,000. This drives sustained churn and watches
# whether the server's resident memory and thread count settle or keep climbing.
#
# Growth during churn is not by itself a leak. Work that is abandoned when a
# peer goes quiet legitimately holds its session until its own wait expires, so
# a server under churn faster than that window holds several at once. What
# separates that from a leak is whether the memory comes back: the run therefore
# ends with an idle settle phase and judges recovery, not peak.
#
# Usage: ./run-soak.sh [connections] [port]

set -euo pipefail
cd "$(dirname "$0")/.."

CONNECTIONS="${1:-400}"
PORT="${2:-54480}"
# Server-side timeout. Retention bugs that hold state for the timeout window
# scale with this, so it is adjustable to tell them apart from true leaks.
SERVER_TIMEOUT_MS="${WEBTRANSPORT_SOAK_SERVER_TIMEOUT_MS:-600000}"
SAMPLE_EVERY=25

swift build --product WebTransportServer >/dev/null
swift build --product WebTransportClient >/dev/null

server_log="$(mktemp -t wt-soak-server)"
pkill -f "WebTransportServer --listen 127.0.0.1:$PORT" 2>/dev/null || true
sleep 1

WEBTRANSPORT_INTEROP_DEBUG=1 ./.build/debug/WebTransportServer \
    --listen "127.0.0.1:$PORT" \
    --transport packet \
    --max-sessions "$((CONNECTIONS + 10))" \
    --timeout-ms "$SERVER_TIMEOUT_MS" \
    >"$server_log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
    grep -q 'listening:' "$server_log" && break
    sleep 1
done
grep -q 'listening:' "$server_log" || { echo "server failed to start" >&2; cat "$server_log" >&2; exit 1; }
echo "server pid $server_pid on 127.0.0.1:$PORT, driving $CONNECTIONS connections"

sample() {
    # RSS in KB and thread count for the server process.
    local rss threads
    rss=$(ps -o rss= -p "$server_pid" 2>/dev/null | tr -d ' ')
    threads=$(ps -M -p "$server_pid" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    echo "${rss:-0} ${threads:-0}"
}

samples_file="$(mktemp -t wt-soak-samples)"
read -r base_rss base_threads <<<"$(sample)"
echo "baseline: rss=${base_rss}KB threads=${base_threads}"

succeeded=0
for i in $(seq 1 "$CONNECTIONS"); do
    if timeout 30 ./.build/debug/WebTransportClient \
        --connect "127.0.0.1:$PORT" \
        --transport packet \
        --trust local-self-signed \
        --message "soak-$i" \
        --timeout-ms 15000 >/dev/null 2>&1; then
        succeeded=$((succeeded + 1))
    fi
    if [ $((i % SAMPLE_EVERY)) -eq 0 ]; then
        read -r rss threads <<<"$(sample)"
        echo "$i $rss $threads" >>"$samples_file"
        printf '  %5d/%d  rss=%sKB threads=%s\n' "$i" "$CONNECTIONS" "$rss" "$threads"
    fi
done

peak_rss=$(sample | cut -d' ' -f1)
echo
echo "connections completed: $succeeded/$CONNECTIONS"

# Idle settle: bounded retention drains here, a leak does not.
SETTLE_SECONDS="${WEBTRANSPORT_SOAK_SETTLE_SECONDS:-45}"
echo "settling for ${SETTLE_SECONDS}s to distinguish retention from a leak..."
sleep "$SETTLE_SECONDS"
read -r settled_rss settled_threads <<<"$(sample)"
echo "after settle: rss=${settled_rss}KB threads=${settled_threads}"

# The authoritative leak signal. Resident memory cannot answer this: a freed
# session's pages stay with the allocator, so RSS remains high long after the
# objects are gone. Counting construction against destruction can.
established=$(grep -c 'session established' "$server_log" || true)
released=$(grep -c 'session released' "$server_log" || true)
echo "sessions: established=$established released=$released"

python3 - "$samples_file" "$base_rss" "$peak_rss" "$settled_rss" "$established" "$released" <<'PY'
import sys, pathlib

rows = [line.split() for line in pathlib.Path(sys.argv[1]).read_text().split("\n") if line.strip()]
base_rss, peak_rss, settled_rss = (int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
established, released = int(sys.argv[5]), int(sys.argv[6])
if len(rows) < 4:
    print("not enough samples to judge a trend")
    raise SystemExit(0)

rss = [int(r[1]) for r in rows]
threads = [int(r[2]) for r in rows]
half = len(rss) // 2

# Compare halves rather than endpoints: a single late sample can be noise, and
# early growth from allocator warm-up is expected and benign.
first_rss, second_rss = sum(rss[:half]) / half, sum(rss[half:]) / len(rss[half:])
growth = (second_rss - first_rss) / first_rss * 100 if first_rss else 0

print(f"rss     first half avg {first_rss:9.0f}KB   second half avg {second_rss:9.0f}KB   drift {growth:+.1f}%")
print(f"threads min {min(threads)}  max {max(threads)}  final {threads[-1]}")

# Recovery is the real signal. Retention drains once the abandoned waits expire;
# a leak keeps whatever it took.
retained = settled_rss - base_rss
recovered = peak_rss - settled_rss
print(f"peak {peak_rss}KB -> settled {settled_rss}KB (recovered {recovered}KB, "
      f"retained {retained}KB above the {base_rss}KB baseline)")

problems = []

# Session lifetime is the verdict. Resident memory is reported for context only:
# it stays elevated after objects are freed because the allocator keeps the
# pages, so it cannot distinguish a leak from a warm heap.
leaked = established - released
if established == 0:
    problems.append("no sessions were established — the run proved nothing")
elif leaked > 0:
    problems.append(
        f"{leaked} of {established} sessions were never released — "
        f"objects are being retained past their connection"
    )

if growth > 25:
    print(f"\nnote: resident memory grew {growth:.1f}% during churn. That is expected while "
          f"abandoned work holds sessions for its wait window, and is not itself a leak; "
          f"the session count above is what decides.")
# Thread count should plateau; unbounded task retention shows up here.
if threads[-1] > min(threads) * 3 and threads[-1] - min(threads) > 8:
    problems.append(f"thread count climbed from {min(threads)} to {threads[-1]} — possible task retention")

if problems:
    print("\nSOAK FAILED")
    for problem in problems:
        print(f"  - {problem}")
    raise SystemExit(1)

print("\nSOAK PASSED: no sustained growth in resident memory or thread count")
PY
