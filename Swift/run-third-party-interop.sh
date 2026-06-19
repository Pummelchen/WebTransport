#!/bin/sh
set -eu

cd "$(dirname "$0")"

proof_dir=".build/external-interop"
tools_dir=".build/external-tools"
mkdir -p "$proof_dir" "$tools_dir"

timeout_ms="${WEBTRANSPORT_THIRD_PARTY_INTEROP_TIMEOUT_MS:-25000}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
aggregate_json="$proof_dir/third-party-latest.json"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/webtransport-third-party-interop.XXXXXX")"
pids=""

cleanup() {
  for pid in $pids; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$work_dir"
}
trap cleanup EXIT

reserve_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

crate_source_dir() {
  crate="$1"
  version="$2"
  for path in "$HOME"/.cargo/registry/src/*/"$crate-$version"; do
    if [ -d "$path" ]; then
      echo "$path"
      return 0
    fi
  done
  cargo info "$crate" >/dev/null
  for path in "$HOME"/.cargo/registry/src/*/"$crate-$version"; do
    if [ -d "$path" ]; then
      echo "$path"
      return 0
    fi
  done
  echo "could not locate Cargo source for $crate $version" >&2
  return 1
}

ensure_cmake() {
  cmake_venv="$tools_dir/cmake-venv"
  if command -v cmake >/dev/null 2>&1; then
    return 0
  fi
  if [ ! -x "$cmake_venv/bin/cmake" ]; then
    python3 -m venv "$cmake_venv"
    "$cmake_venv/bin/python" -m pip install --upgrade pip >/dev/null
    "$cmake_venv/bin/python" -m pip install cmake >/dev/null
  fi
  PATH="$(pwd)/$cmake_venv/bin:$PATH"
  export PATH
}

write_json() {
  python3 - "$@" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

(
    json_file,
    implementation,
    version,
    endpoint,
    settings_validation,
    message,
    attempts,
    client_status,
    server_status,
    stdout_file,
    stderr_file,
    server_stdout_file,
    server_stderr_file,
) = sys.argv[1:]

stdout = pathlib.Path(stdout_file).read_text(errors="replace")
stderr = pathlib.Path(stderr_file).read_text(errors="replace")
server_stdout = pathlib.Path(server_stdout_file).read_text(errors="replace")
server_stderr = pathlib.Path(server_stderr_file).read_text(errors="replace")
proof = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "independentImplementation": implementation,
    "implementationVersion": version,
    "endpoint": endpoint,
    "url": f"https://{endpoint}/",
    "transport": "packet",
    "settingsValidation": settings_validation,
    "message": message,
    "attempts": int(attempts),
    "clientExitCode": int(client_status),
    "serverExitCode": int(server_status),
    "passed": int(client_status) == 0 and "connected" in stdout and message in stdout,
    "clientStdout": stdout,
    "clientStderr": stderr,
    "serverStdout": server_stdout,
    "serverStderr": server_stderr,
}
pathlib.Path(json_file).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
print(json.dumps(proof, indent=2, sort_keys=True))
PY
}

append_aggregate() {
  python3 - "$aggregate_json" "$@" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

aggregate_file = pathlib.Path(sys.argv[1])
proofs = [json.loads(pathlib.Path(path).read_text()) for path in sys.argv[2:]]
summary = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "requiredEndpointCount": 3,
    "passedEndpointCount": sum(1 for proof in proofs if proof.get("passed")),
    "passed": len(proofs) == 3 and all(proof.get("passed") for proof in proofs),
    "endpoints": proofs,
}
aggregate_file.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, indent=2, sort_keys=True))
PY
}

run_pywebtransport() {
  ./run-pywebtransport-interop.sh >/dev/null
  cp "$proof_dir/pywebtransport-latest.json" "$proof_dir/third-party-pywebtransport.json"
  echo "$proof_dir/third-party-pywebtransport.json"
}

run_rust_endpoint() {
  name="$1"
  implementation="$2"
  version="$3"
  crate_dir="$4"
  bind_flag="$5"
  message="$name-interop-$timestamp"

  server_stdout="$proof_dir/third-party-$name-server.stdout"
  server_stderr="$proof_dir/third-party-$name-server.stderr"
  stdout_file="$proof_dir/third-party-$name.stdout"
  stderr_file="$proof_dir/third-party-$name.stderr"
  json_file="$proof_dir/third-party-$name.json"
  : >"$server_stdout"
  : >"$server_stderr"
  : >"$stdout_file"
  : >"$stderr_file"

  attempt=1
  attempts_used=0
  client_status=1
  server_status=0
  endpoint=""
  while [ "$attempt" -le 3 ]; do
    endpoint_dir="$work_dir/$name-$attempt"
    mkdir -p "$endpoint_dir"
    port="$(reserve_port)"
    endpoint="127.0.0.1:$port"
    cert_file="$endpoint_dir/cert.pem"
    key_file="$endpoint_dir/key.pem"
    openssl req -x509 -newkey rsa:2048 \
      -keyout "$key_file" \
      -out "$cert_file" \
      -days 1 \
      -nodes \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

    attempt_server_stdout="$work_dir/$name-$attempt-server.stdout"
    attempt_server_stderr="$work_dir/$name-$attempt-server.stderr"
    (
      cd "$crate_dir"
      RUST_LOG="${WEBTRANSPORT_THIRD_PARTY_RUST_LOG:-info}" \
        cargo run --example echo-server -- "$bind_flag" "$endpoint" --tls-cert "$cert_file" --tls-key "$key_file"
    ) >"$attempt_server_stdout" 2>"$attempt_server_stderr" &
    server_pid=$!
    pids="$pids $server_pid"

    ready=0
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      if grep -q "listening" "$attempt_server_stdout" "$attempt_server_stderr" 2>/dev/null; then
        ready=1
        break
      fi
      if ! kill -0 "$server_pid" 2>/dev/null; then
        break
      fi
      sleep 0.25
    done

    {
      echo "attempt $attempt endpoint=$endpoint ready=$ready"
      cat "$attempt_server_stdout"
    } >>"$server_stdout"
    {
      echo "attempt $attempt endpoint=$endpoint ready=$ready"
      cat "$attempt_server_stderr"
    } >>"$server_stderr"

    if [ "$ready" -eq 1 ]; then
      attempt_stdout="$work_dir/$name-$attempt-client.stdout"
      attempt_stderr="$work_dir/$name-$attempt-client.stderr"
      set +e
      swift run WebTransportClient \
        --connect "$endpoint" \
        --transport packet \
        --authority "$endpoint" \
        --path / \
        --origin none \
        --protocol none \
        --trust local-self-signed \
        --settings-validation chromium-interop \
        --message "$message" \
        --timeout-ms "$timeout_ms" \
        >"$attempt_stdout" 2>"$attempt_stderr"
      client_status=$?
      set -e
      {
        echo "attempt $attempt exit=$client_status"
        cat "$attempt_stdout"
      } >>"$stdout_file"
      {
        echo "attempt $attempt exit=$client_status"
        cat "$attempt_stderr"
      } >>"$stderr_file"
    else
      client_status=127
      {
        echo "attempt $attempt exit=$client_status"
      } >>"$stdout_file"
      {
        echo "attempt $attempt server did not become ready"
      } >>"$stderr_file"
    fi

    set +e
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null
    server_status=$?
    set -e

    attempts_used="$attempt"
    if [ "$ready" -eq 1 ] && [ "$client_status" -eq 0 ] && grep -q "connected" "$attempt_stdout" && grep -q "$message" "$attempt_stdout"; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 0.5
  done

  write_json "$json_file" "$implementation" "$version" "$endpoint" "chromium-interop" "$message" "$attempts_used" "$client_status" "$server_status" "$stdout_file" "$stderr_file" "$server_stdout" "$server_stderr" >/dev/null
  echo "$json_file"
}

swift build --product WebTransportClient
ensure_cmake
quinn_dir="$(crate_source_dir web-transport-quinn 0.11.9)"
quiche_dir="$(crate_source_dir web-transport-quiche 0.4.1)"

py_json="$(run_pywebtransport)"
quinn_json="$(run_rust_endpoint \
  quinn \
  web-transport-quinn \
  "web-transport-quinn 0.11.9" \
  "$quinn_dir" \
  --addr)"
quiche_json="$(run_rust_endpoint \
  quiche \
  web-transport-quiche \
  "web-transport-quiche 0.4.1" \
  "$quiche_dir" \
  --bind)"

append_aggregate "$py_json" "$quinn_json" "$quiche_json"

python3 - "$aggregate_json" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
if not summary["passed"]:
    raise SystemExit(1)
PY
