#!/bin/sh
set -eu

cd "$(dirname "$0")"

if [ -z "${WEBTRANSPORT_EXTERNAL_INTEROP_ENDPOINT:-}" ]; then
  echo "Set WEBTRANSPORT_EXTERNAL_INTEROP_ENDPOINT=host:port, or use ./run-pywebtransport-interop.sh for the local independent proof." >&2
  exit 2
fi

endpoint="$WEBTRANSPORT_EXTERNAL_INTEROP_ENDPOINT"
authority="${WEBTRANSPORT_EXTERNAL_INTEROP_AUTHORITY:-${endpoint%:*}}"
path="${WEBTRANSPORT_EXTERNAL_INTEROP_PATH:-/}"
origin="${WEBTRANSPORT_EXTERNAL_INTEROP_ORIGIN:-none}"
protocol="${WEBTRANSPORT_EXTERNAL_INTEROP_PROTOCOL:-none}"
transport="${WEBTRANSPORT_EXTERNAL_INTEROP_TRANSPORT:-packet}"
trust="${WEBTRANSPORT_EXTERNAL_INTEROP_TRUST:-system}"
exchange="${WEBTRANSPORT_EXTERNAL_INTEROP_EXCHANGE:-auto}"
message="${WEBTRANSPORT_EXTERNAL_INTEROP_MESSAGE:-external-interop-$(date -u +%Y%m%dT%H%M%SZ)}"
timeout_ms="${WEBTRANSPORT_EXTERNAL_INTEROP_TIMEOUT_MS:-15000}"
implementation="${WEBTRANSPORT_EXTERNAL_INTEROP_IMPLEMENTATION:-configured independent WebTransport endpoint}"

proof_dir=".build/external-interop"
mkdir -p "$proof_dir"
stdout_file="$proof_dir/latest.stdout"
stderr_file="$proof_dir/latest.stderr"
json_file="$proof_dir/latest.json"

swift build --product WebTransportClient

set +e
swift run WebTransportClient \
  --connect "$endpoint" \
  --transport "$transport" \
  --authority "$authority" \
  --path "$path" \
  --origin "$origin" \
  --protocol "$protocol" \
  --trust "$trust" \
  --exchange "$exchange" \
  --message "$message" \
  --timeout-ms "$timeout_ms" \
  >"$stdout_file" 2>"$stderr_file"
status=$?
set -e

python3 - "$json_file" "$status" "$implementation" "$endpoint" "$authority" "$path" "$origin" "$protocol" "$transport" "$trust" "$exchange" "$message" "$timeout_ms" "$stdout_file" "$stderr_file" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

(
    json_file,
    status,
    implementation,
    endpoint,
    authority,
    path,
    origin,
    protocol,
    transport,
    trust,
    exchange,
    message,
    timeout_ms,
    stdout_file,
    stderr_file,
) = sys.argv[1:]

stdout = pathlib.Path(stdout_file).read_text(errors="replace")
stderr = pathlib.Path(stderr_file).read_text(errors="replace")
proof = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "independentImplementation": implementation,
    "endpoint": endpoint,
    "authority": authority,
    "path": path,
    "origin": None if origin == "none" else origin,
    "protocol": None if protocol == "none" else protocol,
    "transport": transport,
    "trust": trust,
    "exchange": exchange,
    "message": message,
    "timeoutMilliseconds": int(timeout_ms),
    "exitCode": int(status),
    "passed": int(status) == 0 and "connected" in stdout and f"exchange={exchange}" in stdout and message in stdout,
    "stdout": stdout,
    "stderr": stderr,
}
pathlib.Path(json_file).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
PY

cat "$json_file"

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

if ! grep -q "connected" "$stdout_file" || ! grep -q "exchange=$exchange" "$stdout_file" || ! grep -q "$message" "$stdout_file"; then
  echo "external interop did not produce connected echo proof" >&2
  exit 1
fi
