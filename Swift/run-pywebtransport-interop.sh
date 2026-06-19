#!/bin/sh
set -eu

cd "$(dirname "$0")"

message="${WEBTRANSPORT_PYWEBTRANSPORT_INTEROP_MESSAGE:-pywebtransport-interop-$(date -u +%Y%m%dT%H%M%SZ)}"
timeout_ms="${WEBTRANSPORT_PYWEBTRANSPORT_INTEROP_TIMEOUT_MS:-15000}"
proof_dir=".build/external-interop"
venv_dir="$proof_dir/pywebtransport-venv"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/webtransport-pywebtransport-interop.XXXXXX")"
mkdir -p "$proof_dir"
trap 'rm -rf "$work_dir"; if [ -n "${server_pid:-}" ] && kill -0 "$server_pid" 2>/dev/null; then kill "$server_pid" 2>/dev/null || true; fi' EXIT

if [ ! -x "$venv_dir/bin/python" ]; then
  python3 -m venv "$venv_dir"
  "$venv_dir/bin/python" -m pip install --upgrade pip >/dev/null
fi
"$venv_dir/bin/python" -m pip install pywebtransport==0.1.2 >/dev/null

swift build --product WebTransportClient

server_script="$work_dir/pywebtransport_echo_server.py"
cat > "$server_script" <<'PY'
import asyncio
import contextlib
import logging
import os
import socket
import sys

from pywebtransport.config import ServerConfig
from pywebtransport.server.app import ServerApp
from pywebtransport.session import WebTransportSession
from pywebtransport.stream import WebTransportStream
from pywebtransport.utils import generate_self_signed_cert


def reserve_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def echo_stream(stream: WebTransportStream) -> None:
    async for data in stream.read_iter():
        await stream.write(data)
    await stream.close()


async def echo_handler(session: WebTransportSession) -> None:
    async def datagrams() -> None:
        while not session.is_closed:
            data = await session.datagrams.receive()
            if data:
                await session.datagrams.send(data)

    async def streams() -> None:
        async for stream in session.incoming_streams():
            if isinstance(stream, WebTransportStream):
                asyncio.create_task(echo_stream(stream))

    await asyncio.gather(datagrams(), streams())


async def main() -> None:
    work_dir = os.environ["PYWEBTRANSPORT_INTEROP_WORK_DIR"]
    debug = os.environ.get("WEBTRANSPORT_INTEROP_DEBUG") == "1"
    logging.basicConfig(level=logging.DEBUG if debug else logging.WARNING)
    port = int(os.environ.get("PYWEBTRANSPORT_INTEROP_PORT") or reserve_port())
    certfile, keyfile = generate_self_signed_cert("127.0.0.1", output_dir=work_dir, days_valid=1)
    config = ServerConfig(
        bind_host="127.0.0.1",
        bind_port=port,
        certfile=certfile,
        keyfile=keyfile,
        verify_mode=0,
        alpn_protocols=["h3"],
        debug=debug,
        access_log=False,
        log_level="DEBUG" if debug else "WARNING",
    )
    app = ServerApp(config=config)
    app.route("/")(echo_handler)
    async with app:
        await app.server.listen(host="127.0.0.1", port=port)
        actual = app.server.local_address
        print(f"pywebtransport listening: {actual[0]}:{actual[1]}", flush=True)
        await app.server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"pywebtransport server failed: {exc}", file=sys.stderr, flush=True)
        raise
PY

server_stdout="$work_dir/server.stdout"
server_stderr="$work_dir/server.stderr"
PYWEBTRANSPORT_INTEROP_WORK_DIR="$work_dir" "$venv_dir/bin/python" "$server_script" >"$server_stdout" 2>"$server_stderr" &
server_pid=$!

endpoint=""
deadline=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -q "pywebtransport listening:" "$server_stdout"; then
    endpoint="$(sed -n 's/^pywebtransport listening: //p' "$server_stdout" | tail -1)"
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$server_stderr" >&2 || true
    exit 1
  fi
  sleep 0.05
done

if [ -z "$endpoint" ]; then
  echo "pywebtransport server did not report a listening endpoint" >&2
  cat "$server_stdout" >&2 || true
  cat "$server_stderr" >&2 || true
  exit 1
fi

stdout_file="$proof_dir/pywebtransport.stdout"
stderr_file="$proof_dir/pywebtransport.stderr"
json_file="$proof_dir/pywebtransport-latest.json"

attempt=1
attempts_used=0
status=1
: >"$stdout_file"
: >"$stderr_file"
while [ "$attempt" -le 3 ]; do
  attempt_stdout="$work_dir/client-$attempt.stdout"
  attempt_stderr="$work_dir/client-$attempt.stderr"
  set +e
  swift run WebTransportClient \
    --connect "$endpoint" \
    --transport packet \
    --authority "$endpoint" \
    --path / \
    --origin none \
    --protocol none \
    --trust local-self-signed \
    --settings-validation pywebtransport-stream-interop \
    --message "$message" \
    --timeout-ms "$timeout_ms" \
    >"$attempt_stdout" 2>"$attempt_stderr"
  status=$?
  set -e
  {
    echo "attempt $attempt exit=$status"
    cat "$attempt_stdout"
  } >>"$stdout_file"
  {
    echo "attempt $attempt exit=$status"
    cat "$attempt_stderr"
  } >>"$stderr_file"
  attempts_used="$attempt"
  if [ "$status" -eq 0 ] && grep -q "connected" "$attempt_stdout" && grep -q "$message" "$attempt_stdout"; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.5
done

set +e
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null
server_status=$?
set -e
server_pid=""

cp "$server_stdout" "$proof_dir/pywebtransport-server.stdout"
cp "$server_stderr" "$proof_dir/pywebtransport-server.stderr"

"$venv_dir/bin/python" - "$json_file" "$status" "$server_status" "$endpoint" "$message" "$attempts_used" "$stdout_file" "$stderr_file" "$server_stdout" "$server_stderr" <<'PY'
import importlib.metadata
import json
import pathlib
import sys
from datetime import datetime, timezone

json_file, status, server_status, endpoint, message, attempts, stdout_file, stderr_file, server_stdout, server_stderr = sys.argv[1:]
stdout = pathlib.Path(stdout_file).read_text(errors="replace")
stderr = pathlib.Path(stderr_file).read_text(errors="replace")
server_out = pathlib.Path(server_stdout).read_text(errors="replace")
server_err = pathlib.Path(server_stderr).read_text(errors="replace")
proof = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "independentImplementation": "pywebtransport/aioquic",
    "implementationVersion": f"pywebtransport {importlib.metadata.version('pywebtransport')}, aioquic {importlib.metadata.version('aioquic')}",
    "endpoint": endpoint,
    "url": f"https://{endpoint}/",
    "transport": "packet",
    "settingsValidation": "pywebtransport-stream-interop",
    "message": message,
    "attempts": int(attempts),
    "clientExitCode": int(status),
    "serverExitCode": int(server_status),
    "passed": int(status) == 0 and "connected" in stdout and message in stdout,
    "clientStdout": stdout,
    "clientStderr": stderr,
    "serverStdout": server_out,
    "serverStderr": server_err,
}
pathlib.Path(json_file).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
print(json.dumps(proof, indent=2, sort_keys=True))
PY

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

if ! grep -q "connected" "$stdout_file" || ! grep -q "$message" "$stdout_file"; then
  echo "pywebtransport interop did not produce connected echo proof" >&2
  exit 1
fi
