#!/bin/sh
# The C99 client against the five independent implementations on a routable host (Phase 11, WT-135).
#
# The container matrix (`run-container-interop.sh`) puts both ends on one Docker network with a
# self-signed certificate, which proves the protocol and nothing about trust. This runs the C99
# client against peers that present a CA-issued certificate, with `--trust system`, so the chain is
# validated against the platform trust store AND the name is checked. That is the difference the
# plan's Phase 11 asks for, and it is why every case here passes `--authority`.
#
# The transport ADDRESS and the IDENTITY are separate on purpose: the client reaches the peer by
# address, while the name the certificate must prove comes from `--authority`. Without the split the
# client would have to resolve the name itself, which the C99 endpoint parser does not do.
#
# Required environment:
#   WEBTRANSPORT_VPS_INTEROP_AUTHORITY  the name the peers' certificate carries
#                                    (default pummelchen.91.99.176.243.nip.io)
#   WEBTRANSPORT_VPS_INTEROP_ADDRESS   the address to reach them on (default 91.99.176.243)
# Optional:
#   WEBTRANSPORT_VPS_INTEROP_PY_PORT       (54001)   WEBTRANSPORT_VPS_INTEROP_QUINN_PORT  (54002)
#   WEBTRANSPORT_VPS_INTEROP_QUICHE_PORT   (54003)   WEBTRANSPORT_VPS_INTEROP_H3_PORT     (54005)
#   WEBTRANSPORT_VPS_INTEROP_ERLANG_PORT   (54007)
#   WEBTRANSPORT_VPS_INTEROP_TIMEOUT_MS    (15000)
#   WEBTRANSPORT_VPS_INTEROP_CLIENT        path to wt-client-c99
#   WEBTRANSPORT_VPS_INTEROP_OUT           where the proofs are written (C99/out/vps-interop)
#
# Usage:  C99/scripts/run-vps-third-party-interop.sh [proof ...]
#         (no arguments runs all seven)
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"

authority="${WEBTRANSPORT_VPS_INTEROP_AUTHORITY:-pummelchen.91.99.176.243.nip.io}"
address="${WEBTRANSPORT_VPS_INTEROP_ADDRESS:-91.99.176.243}"
timeout_ms="${WEBTRANSPORT_VPS_INTEROP_TIMEOUT_MS:-15000}"
out="${WEBTRANSPORT_VPS_INTEROP_OUT:-$root/out/vps-interop}"

py_port="${WEBTRANSPORT_VPS_INTEROP_PY_PORT:-54001}"
quinn_port="${WEBTRANSPORT_VPS_INTEROP_QUINN_PORT:-54002}"
quiche_port="${WEBTRANSPORT_VPS_INTEROP_QUICHE_PORT:-54003}"
h3_port="${WEBTRANSPORT_VPS_INTEROP_H3_PORT:-54005}"
erlang_port="${WEBTRANSPORT_VPS_INTEROP_ERLANG_PORT:-54007}"

# The client is found rather than assumed: the caller may have built it anywhere, and a matrix that
# silently ran a stale binary would be worse than one that refused to run.
client="${WEBTRANSPORT_VPS_INTEROP_CLIENT:-}"
if [ -z "$client" ]; then
  for candidate in "$root/out/debian/build-release/apps/wt-client-c99" \
                   "$root/out/debian/build/apps/wt-client-c99" \
                   "$root/out/macos26/build-release/apps/wt-client-c99" \
                   "$root/out/macos26/build/apps/wt-client-c99"; do
    [ -x "$candidate" ] && client="$candidate" && break
  done
fi
[ -n "$client" ] && [ -x "$client" ] || {
  echo "vps interop: no wt-client-c99 found; build it or set WEBTRANSPORT_VPS_INTEROP_CLIENT"
  exit 2
}

mkdir -p "$out"

# One proof: implementation, exchange, port, and the message whose echo is the evidence. The message
# is NAMED rather than empty because an empty WebTransport stream carries nothing a peer can observe.
run_proof() {
  key="$1" implementation="$2" exchange="$3" peer_address="$4" port="$5"
  message="$key-$exchange-vps"
  stdout_file="$out/$key-$exchange.stdout"
  json_file="$out/$key-$exchange.json"

  set +e
  "$client" --connect "$peer_address:$port" --authority "$authority" --trust system \
    --exchange "$exchange" --message "$message" --timeout-ms "$timeout_ms" --json \
    >"$stdout_file" 2>&1
  status=$?
  set -e

  python3 - "$json_file" "$implementation" "$authority" "$peer_address" "$port" "$exchange" \
    "$message" "$timeout_ms" "$status" "$stdout_file" <<'PY'
import json
import pathlib
import sys

(json_file, implementation, authority, address, port, exchange,
 message, timeout_ms, status, stdout_file) = sys.argv[1:]

report = {}
for line in pathlib.Path(stdout_file).read_text(errors="replace").splitlines():
    line = line.strip()
    if line.startswith("{") and '"role":"client"' in line:
        try:
            report = json.loads(line)
        except json.JSONDecodeError:
            report = {}

# A proof passes on the session AND the exchange: a peer that accepted a CONNECT but echoed nothing
# would otherwise count, and the echo is the whole point of an interop proof.
passed = (
    int(status) == 0
    and report.get("status") == "ok"
    and report.get("established") is True
    and report.get("connectAccepted") is True
    and report.get("responseStatus") == 200
    and int(report.get("receivedBytes", 0) or 0) > 0
)

proof = {
    "key": f"{implementation.split()[0]}-{exchange}",
    "implementation": implementation,
    "exchange": exchange,
    "endpoint": f"{address}:{port}",
    "authority": authority,
    "trust": "system",
    "message": message,
    "timeoutMilliseconds": int(timeout_ms),
    "exitCode": int(status),
    "passed": passed,
    "status": report.get("status"),
    "established": report.get("established"),
    "connectAccepted": report.get("connectAccepted"),
    "responseStatus": report.get("responseStatus"),
    "receivedBytes": report.get("receivedBytes"),
}
pathlib.Path(json_file).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
print(f"{'PASS' if passed else 'FAIL'}  {implementation:<24} {exchange:<9} "
      f"status={report.get('status')} receivedBytes={report.get('receivedBytes')}")
PY
}

if [ "$#" -gt 0 ]; then
  proofs="$*"
else
  proofs="pywebtransport quinn quinn-datagram quiche h3 erlang erlang-datagram"
fi

# A peer may sit on the shared address or on one of its own: the VPS publishes all five on one host,
# while a container-network deployment gives each its own. An override wins when it is set.
address_for() {
  eval "override=\${WEBTRANSPORT_VPS_INTEROP_$1_ADDRESS:-}"
  [ -n "$override" ] && printf '%s' "$override" || printf '%s' "$address"
}

for proof in $proofs; do
  case "$proof" in
    pywebtransport)  run_proof pywebtransport "pywebtransport / aioquic" stream   "$(address_for PY)"     "$py_port" ;;
    quinn)           run_proof quinn          "web-transport-quinn"     stream   "$(address_for QUINN)"  "$quinn_port" ;;
    quinn-datagram)  run_proof quinn          "web-transport-quinn"     datagram "$(address_for QUINN)"  "$quinn_port" ;;
    quiche)          run_proof quiche         "web-transport-quiche"    stream   "$(address_for QUICHE)" "$quiche_port" ;;
    h3)              run_proof h3             "hyperium/h3-webtransport" datagram "$(address_for H3)"    "$h3_port" ;;
    erlang)          run_proof erlang         "erlang-webtransport"     stream   "$(address_for ERLANG)" "$erlang_port" ;;
    erlang-datagram) run_proof erlang         "erlang-webtransport"     datagram "$(address_for ERLANG)" "$erlang_port" ;;
    erlang-datagram) run_proof erlang         "erlang-webtransport"     datagram "$erlang_port" ;;
    *) echo "vps interop: unknown proof $proof"; exit 2 ;;
  esac
done

# The aggregate the plan names, counted from the proof files rather than from what this script
# expected to happen.
python3 - "$out" "$authority" "$address" <<'PY'
import json
import pathlib
import sys

out, authority, address = sys.argv[1:]
proofs = []
for path in sorted(pathlib.Path(out).glob("*.json")):
    if path.name == "summary.json":
        continue
    proofs.append(json.loads(path.read_text()))

implementations = sorted({p["implementation"] for p in proofs})
passed = [p for p in proofs if p["passed"]]
failed = [p for p in proofs if not p["passed"]]

summary = {
    "authority": authority,
    "address": address,
    "testedImplementationCount": len(implementations),
    "passedProofCount": len(passed),
    "requiredProofCount": len(proofs),
    "allPassed": len(failed) == 0 and len(proofs) > 0,
    "implementations": implementations,
    "failedProofs": [f'{p["implementation"]}-{p["exchange"]}' for p in failed],
}
pathlib.Path(out, "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

print()
print(f"vps interop: {len(passed)}/{len(proofs)} proofs passed across "
      f"{len(implementations)} implementation(s)")
if failed:
    print("failed: " + ", ".join(summary["failedProofs"]))
sys.exit(0 if summary["allPassed"] else 1)
PY
