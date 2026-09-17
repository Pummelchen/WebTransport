#!/bin/sh
# The Swift client against the five independent implementations on the VPS (Phase 11's Swift half).
#
# The transport ADDRESS and the IDENTITY are separate on purpose, and the split is the point of the run rather than
# a convenience: `WEBTRANSPORT_VPS_INTEROP_ADDRESS` is what the client dials and `WEBTRANSPORT_VPS_INTEROP_AUTHORITY`
# is the name the request carries and the server's certificate has to prove. The deployed certificate covers
# `pummelchen.91.99.176.243.nip.io` and carries no address at all, so dialling the address for that name is exactly
# the case the certificate validator has to handle, and naming a name the certificate does not carry must still be
# refused. Both were measured on 17 September 2026: the pair above connects, `--authority wrong.example.com` (and
# the pre-WT-261 behaviour of validating against the dialled address) fails the handshake, and the peer logs
# `Connection close received (code 0x12A/0x12E, reason TLS alert error)` while the client reports only its timeout.
# Before WT-261 the Swift client validated against the address it dialled, which is why this runner used to dial the
# certificate's own name and could not express the split at all.
set -eu

cd "$(dirname "$0")"

address="${WEBTRANSPORT_VPS_INTEROP_ADDRESS:-91.99.176.243}"
authority="${WEBTRANSPORT_VPS_INTEROP_AUTHORITY:-pummelchen.91.99.176.243.nip.io}"
os_name="${WEBTRANSPORT_VPS_INTEROP_OS:-Debian GNU/Linux 13 (trixie) x86_64}"
test_date="${WEBTRANSPORT_VPS_INTEROP_DATE:-20 June 2026}"
timeout_ms="${WEBTRANSPORT_VPS_INTEROP_TIMEOUT_MS:-60000}"
proof_dir=".build/external-interop"
mkdir -p "$proof_dir"

swift build --product WebTransportClient

run_case() {
  key="$1"
  implementation="$2"
  version="$3"
  url="$4"
  port="$5"
  exchange="$6"
  settings_validation="$7"
  expected_message="$key-$exchange-vps"
  expected_response="${8:-$expected_message}"
  stdout_file="$proof_dir/vps-$key-$exchange.stdout"
  stderr_file="$proof_dir/vps-$key-$exchange.stderr"
  json_file="$proof_dir/vps-$key-$exchange.json"

  set +e
  swift run WebTransportClient \
    --connect "$address:$port" \
    --transport packet \
    --authority "$authority:$port" \
    --path / \
    --origin none \
    --protocol none \
    --trust system \
    --settings-validation "$settings_validation" \
    --exchange "$exchange" \
    --message "$expected_message" \
    --timeout-ms "$timeout_ms" \
    >"$stdout_file" 2>"$stderr_file"
  status=$?
  set -e

  python3 - "$json_file" "$implementation" "$version" "$url" "$authority" "$address" "$port" "$os_name" "$test_date" "$exchange" "$expected_message" "$expected_response" "$settings_validation" "$status" "$stdout_file" "$stderr_file" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

(
    json_file,
    implementation,
    version,
    url,
    authority,
    address,
    port,
    os_name,
    test_date,
    exchange,
    message,
    expected_response,
    settings_validation,
    status,
    stdout_file,
    stderr_file,
) = sys.argv[1:]

stdout = pathlib.Path(stdout_file).read_text(errors="replace")
stderr = pathlib.Path(stderr_file).read_text(errors="replace")
# `endpoint` is what was dialled and `authority` is the name that was asked for and verified; the URL is built from
# the name, because that is the identity the request carries.
endpoint = f"{address}:{port}"
proof = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "testDate": test_date,
    "thirdPartyOS": os_name,
    "independentImplementation": implementation,
    "implementationVersion": version,
    "implementationURL": url,
    "endpoint": endpoint,
    "authority": f"{authority}:{port}",
    "url": f"https://{authority}:{port}/",
    "transport": "packet",
    "settingsValidation": settings_validation,
    "exchange": exchange,
    "message": message,
    "expectedResponse": expected_response,
    "exitCode": int(status),
    "passed": int(status) == 0 and "connected" in stdout and f"exchange={exchange}" in stdout and expected_response in stdout,
    "stdout": stdout,
    "stderr": stderr,
}
pathlib.Path(json_file).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
print(json.dumps(proof, indent=2, sort_keys=True))
PY
  echo "$json_file"
}

py_json="$(run_case pywebtransport "pywebtransport / aioquic" "pywebtransport 0.1.2, aioquic 1.3.0" "https://pypi.org/project/pywebtransport/" 54001 stream pywebtransport-stream-interop | tail -1)"
quinn_stream_json="$(run_case web-transport-quinn "web-transport-quinn" "0.11.9" "https://crates.io/crates/web-transport-quinn/0.11.9" 54002 stream chromium-interop | tail -1)"
quinn_datagram_json="$(run_case web-transport-quinn "web-transport-quinn" "0.11.9" "https://crates.io/crates/web-transport-quinn/0.11.9" 54002 datagram chromium-interop | tail -1)"
quiche_json="$(run_case web-transport-quiche "web-transport-quiche" "0.4.1" "https://crates.io/crates/web-transport-quiche/0.4.1" 54003 stream chromium-interop | tail -1)"
h3_json="$(run_case h3-webtransport "hyperium/h3-webtransport" "0.1.2 / hyperium h3 main example" "https://github.com/hyperium/h3/tree/master/h3-webtransport" 54005 datagram chromium-interop | tail -1)"
erlang_stream_json="$(run_case erlang-webtransport "erlang-webtransport" "main f2d4d8dfe60c" "https://github.com/benoitc/erlang-webtransport" 54007 stream draft16-strict "echo: erlang-webtransport-stream-vps" | tail -1)"
erlang_datagram_json="$(run_case erlang-webtransport "erlang-webtransport" "main f2d4d8dfe60c" "https://github.com/benoitc/erlang-webtransport" 54007 datagram draft16-strict "echo: erlang-webtransport-datagram-vps" | tail -1)"

python3 - "$proof_dir/vps-third-party-latest.json" "$py_json" "$quinn_stream_json" "$quinn_datagram_json" "$quiche_json" "$h3_json" "$erlang_stream_json" "$erlang_datagram_json" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

aggregate = pathlib.Path(sys.argv[1])
proofs = [json.loads(pathlib.Path(path).read_text()) for path in sys.argv[2:]]
implementations = sorted({proof["independentImplementation"] for proof in proofs})
passed = [proof for proof in proofs if proof.get("passed")]
summary = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "requiredImplementationCount": 5,
    "testedImplementationCount": len(implementations),
    "requiredProofCount": 7,
    "passedProofCount": len(passed),
    "allPassed": len(proofs) == 7 and all(proof.get("passed") for proof in proofs),
    "requiredExchanges": ["stream", "datagram"],
    "implementations": implementations,
    "proofs": proofs,
}
aggregate.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, indent=2, sort_keys=True))
if not summary["allPassed"]:
    raise SystemExit(1)
PY
