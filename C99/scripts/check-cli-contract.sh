#!/bin/sh
# The CLI tools' process contract (Phase 10, the "CLI process behavior" group).
#
# Scripts drive these tools, so their EXIT STATUSES and their rejected command lines are part of the interface:
# a tool that exits 0 after failing to connect is a tool a script cannot use, and an unsupported mode that is
# silently ignored is a report nobody can trust. This checks the contract without a peer, which is what makes it
# fast enough to run on every build.
set -eu

client="$1"
server="$2"
conformance="$3"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  echo "cli contract: $1"
  shift
  for file in "$@"; do
    echo "--- $file:"; cat "$file"
  done
  exit 1
}

# A usage error is 2, and never a quiet success.
set +e
"$client" --transport quic >"$work/out" 2>"$work/err"
status=$?
set -e
[ "$status" -eq 2 ] || fail "an unsupported transport must exit 2 (got $status)" "$work/err"
grep -q "unsupported transport" "$work/err" || fail "and say which mode it refused" "$work/err"

set +e
"$client" >"$work/out" 2>"$work/err"
status=$?
set -e
[ "$status" -eq 2 ] || fail "no mode must exit 2 (got $status)" "$work/err"

set +e
"$server" --transport anything >"$work/out" 2>"$work/err"
status=$?
set -e
[ "$status" -eq 2 ] || fail "the server refuses an unsupported transport too (got $status)" "$work/err"

set +e
"$conformance" --scenario one >"$work/out" 2>"$work/err"
status=$?
set -e
[ "$status" -eq 2 ] || fail "an unsupported scenario must exit 2 (got $status)" "$work/err"

# --help is a success, and says what the tool is.
set +e
"$client" --help >"$work/out" 2>&1
status=$?
set -e
[ "$status" -eq 0 ] || fail "--help must exit 0 (got $status)" "$work/out"
grep -q "usage:" "$work/out" || fail "--help must print a usage line" "$work/out"

# A client that cannot reach anybody exits NON-ZERO and says so in its report: a timeout is not a session, and a
# script must be able to tell the difference without parsing prose. Port 9 (discard) is the polite way to have
# nobody there.
set +e
"$client" --connect 127.0.0.1:9 --origin localhost --timeout-ms 300 --json >"$work/out" 2>"$work/err"
status=$?
set -e
[ "$status" -ne 0 ] || fail "a client that never connected must not exit 0" "$work/out"
grep -q '"role":"client"' "$work/out" || fail "and must report in JSON when asked" "$work/out"
grep -q '"established":false' "$work/out" || fail "with established false" "$work/out"
grep -q '"status":"ok"' "$work/out" && fail "and must NOT claim ok" "$work/out"

# The conformance tool's report is machine-readable and its summary is consistent with its scenarios.
"$conformance" --scenario all --json >"$work/out" 2>"$work/err"
grep -q '"summary":{"total":12' "$work/out" || fail "the conformance summary must count twelve scenarios" "$work/out"
grep -q '"passed":12,"failed":0,"unsupported":0' "$work/out" \
  || fail "and every scenario must pass on this machine (IPv6 reports unsupported only where it is absent)" "$work/out"

echo "cli contract: exit statuses, refusals and the JSON report all hold"
