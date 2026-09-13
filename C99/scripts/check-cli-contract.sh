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
# Exit 3 means "nothing failed but something was not attempted", which is the report's own distinction and not a
# failure of this script.
set +e
"$conformance" --scenario all --json >"$work/out" 2>"$work/err"
conformance_status=$?
set -e
[ "$conformance_status" -eq 0 ] || [ "$conformance_status" -eq 3 ] \
  || fail "the conformance tool must exit 0 or 3 (got $conformance_status)" "$work/err"
grep -q '"summary":{"total":17' "$work/out" || fail "the conformance summary must count seventeen scenarios" "$work/out"
grep -q '"failed":0' "$work/out" || fail "and no scenario may fail" "$work/out"
# `unsupported` is allowed -- IPv6 reports itself where the machine has no IPv6 loopback -- and IF a scenario is
# unsupported it must carry a NON-EMPTY reason. The check is conditional because a run with no unsupported
# scenarios is the healthy case: an unconditional grep here failed the moment WT-137 was fixed and the last
# unsupported entry disappeared.
if grep -q '"unsupported":[1-9]' "$work/out"; then
  grep -q '"result":"unsupported","detail":"' "$work/out" \
    || fail "an unsupported scenario must carry its reason" "$work/out"
  grep -q '"result":"unsupported","detail":""' "$work/out" \
    && fail "and the reason must not be empty" "$work/out"
fi

echo "cli contract: exit statuses, refusals and the JSON report all hold"
