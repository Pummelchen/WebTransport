#!/bin/bash
#
# Runs the WebTransport client against independent third-party implementations
# hosted in local Docker containers, and writes the same proof JSON shape as
# run-vps-third-party-interop.sh.
#
# This exists because the VPS matrix requires a reachable external host, which
# makes interop evidence unavailable to anyone without access to that host and
# unavailable in CI. Containers give the same class of evidence — the Swift
# client talking to an implementation it shares no code with — reproducibly on
# any machine with Docker.
#
# It is NOT a replacement for the VPS matrix. These peers run on loopback with
# self-signed certificates, so they exercise protocol interop but not platform
# certificate validation or a real network path. Both should be green before a
# release claim.
#
# Usage:  ./run-docker-interop.sh [implementation ...]
#         (no arguments runs every implementation)

set -euo pipefail

cd "$(dirname "$0")"

proof_dir="../.build/docker-interop"
timeout_ms="${WEBTRANSPORT_DOCKER_INTEROP_TIMEOUT_MS:-20000}"
mkdir -p "$proof_dir"

if ! docker info >/dev/null 2>&1; then
    echo "error: Docker is not available" >&2
    exit 1
fi

# name | port | image tag | build context | settings-validation | exchanges
IMPLEMENTATIONS=(
    "pywebtransport|54001|wt-interop-pywebtransport|interop-docker/pywebtransport|pywebtransport-stream-interop|stream datagram"
    "quinn|54002|wt-interop-quinn|interop-docker/quinn|chromium-interop|stream datagram"
)

selected=("$@")

is_selected() {
    [ ${#selected[@]} -eq 0 ] && return 0
    for candidate in "${selected[@]}"; do
        [ "$candidate" = "$1" ] && return 0
    done
    return 1
}

cleanup() {
    for entry in "${IMPLEMENTATIONS[@]}"; do
        IFS='|' read -r name _ _ _ _ _ <<<"$entry"
        docker rm -f "wt-interop-$name" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

swift build --product WebTransportClient
client="../.build/debug/WebTransportClient"

proof_files=()
failures=0

for entry in "${IMPLEMENTATIONS[@]}"; do
    IFS='|' read -r name port image context validation exchanges <<<"$entry"
    is_selected "$name" || continue

    echo "==> building $name"
    docker build -q -t "$image" "$context" >/dev/null

    docker rm -f "wt-interop-$name" >/dev/null 2>&1 || true
    docker run -d --name "wt-interop-$name" -p "$port:$port/udp" -e "PORT=$port" "$image" >/dev/null

    # Wait for the container to bind rather than sleeping a fixed interval.
    for _ in $(seq 1 30); do
        if docker logs "wt-interop-$name" 2>&1 | grep -qiE 'listening|running'; then
            break
        fi
        sleep 1
    done

    for exchange in $exchanges; do
        message="$name-$exchange-docker"
        stdout_file="$proof_dir/$name-$exchange.stdout"
        stderr_file="$proof_dir/$name-$exchange.stderr"
        json_file="$proof_dir/$name-$exchange.json"

        # Docker Desktop publishes the UDP port through a VM proxy that can lag
        # the container's own bind, so the first datagram after startup is
        # sometimes dropped with no ICMP to signal it. Retry a few times before
        # calling it an interop failure; a real incompatibility fails every
        # attempt, a startup race clears on the second.
        attempt=0
        status=1
        while [ "$attempt" -lt 3 ]; do
            attempt=$((attempt + 1))
            set +e
            "$client" \
                --connect "127.0.0.1:$port" \
                --transport packet \
                --authority "127.0.0.1:$port" \
                --path / \
                --origin none \
                --protocol none \
                --trust local-self-signed \
                --settings-validation "$validation" \
                --exchange "$exchange" \
                --message "$message" \
                --timeout-ms "$timeout_ms" \
                >"$stdout_file" 2>"$stderr_file"
            status=$?
            set -e
            [ "$status" -eq 0 ] && break
            sleep 2
        done

        python3 - "$json_file" "$name" "$exchange" "$message" "127.0.0.1:$port" "$validation" "$status" \
            "$stdout_file" "$stderr_file" "$attempt" <<'PY'
import json, pathlib, sys
from datetime import datetime, timezone

(json_file, implementation, exchange, message, endpoint,
 settings_validation, status, stdout_file, stderr_file, attempts) = sys.argv[1:]

stdout = pathlib.Path(stdout_file).read_text(errors="replace")
stderr = pathlib.Path(stderr_file).read_text(errors="replace")
proof = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "harness": "docker-local",
    "independentImplementation": implementation,
    "endpoint": endpoint,
    "transport": "packet",
    "trust": "local-self-signed",
    "settingsValidation": settings_validation,
    "exchange": exchange,
    "message": message,
    "exitCode": int(status),
    "attempts": int(attempts),
    "passed": int(status) == 0
              and "connected" in stdout
              and f"exchange={exchange}" in stdout
              and message in stdout,
    "stdout": stdout,
    "stderr": stderr,
}
pathlib.Path(json_file).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
retried = f" (after {proof['attempts']} attempts)" if proof["attempts"] > 1 else ""
print(("PASS" if proof["passed"] else "FAIL") + f"  {implementation} {exchange}{retried}")
PY
        proof_files+=("$json_file")
        [ "$status" -eq 0 ] || failures=$((failures + 1))
    done

    docker rm -f "wt-interop-$name" >/dev/null 2>&1 || true
done

python3 - "$proof_dir/docker-interop-latest.json" "${proof_files[@]}" <<'PY'
import json, pathlib, sys
from datetime import datetime, timezone

aggregate = pathlib.Path(sys.argv[1])
proofs = [json.loads(pathlib.Path(p).read_text()) for p in sys.argv[2:]]
implementations = sorted({p["independentImplementation"] for p in proofs})
passed = [p for p in proofs if p.get("passed")]
summary = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "harness": "docker-local",
    "testedImplementationCount": len(implementations),
    "proofCount": len(proofs),
    "passedProofCount": len(passed),
    "allPassed": bool(proofs) and all(p.get("passed") for p in proofs),
    "implementations": implementations,
    "exchanges": sorted({p["exchange"] for p in proofs}),
    "proofs": proofs,
}
aggregate.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(f"\n{len(passed)}/{len(proofs)} proofs passed across {len(implementations)} implementations")
print(f"aggregate: {aggregate}")
if not summary["allPassed"]:
    raise SystemExit(1)
PY
