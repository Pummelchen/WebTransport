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

# The development trust bypass is restricted to LOOPBACK names, and the restriction is a security rule rather
# than a convenience: a bypass that accepted any name is one a deployment could enable by accident. The library
# enforces it in the trust policy (with its own test), and the TOOL refuses the combination before it does any
# I/O -- which is the half no test asserted, so a refactor that dropped the check would have passed everything
# (WT-180, mirroring the Swift suite's `localSelfSignedTrustPolicyIsLoopbackOnly`).
set +e
"$client" --connect example.com:443 --trust local-development >"$work/out" 2>"$work/err"
status=$?
set -e
[ "$status" -eq 2 ] || fail "the bypass on a real host must exit 2 (got $status)" "$work/err"
grep -q "refused for a non-loopback address" "$work/err" \
  || fail "and say why the bypass was refused" "$work/err"
# And the loopback forms are still accepted, so the refusal is about the ADDRESS and not about the mode.
for loopback in localhost 127.0.0.1 "[::1]"; do
  set +e
  "$client" --connect "$loopback:1" --trust local-development --timeout-ms 200 >"$work/out" 2>"$work/err"
  status=$?
  set -e
  # Whatever the connection does (nothing is listening on port 1), it is not the ARGUMENT refusal: exit 2 with
  # that message would mean the loopback form was turned away too.
  grep -q "refused for a non-loopback address" "$work/err" \
    && fail "$loopback must be allowed to use the bypass" "$work/err"
done

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

# --help must describe the tool that exists. It said "the tool does not yet drive a session over a socket" for
# several phases after the tools started driving one -- a user reading --help was told the tool could not do what
# the CTest suite proved it does twice a minute. The check is the phrase rather than the wording, so the text can
# be improved without editing this.
for tool in "$client" "$server" "$conformance"; do
  set +e
  "$tool" --help >"$work/help" 2>&1
  help_status=$?
  set -e
  [ "$help_status" -eq 0 ] || fail "--help must exit 0 for every tool (got $help_status)" "$work/help"
  grep -q "does not yet" "$work/help" \
    && fail "--help must not claim the tool is unimplemented" "$work/help"
done

# The conformance tool's report is machine-readable and its summary is consistent with its scenarios.
# Exit 3 means "nothing failed but something was not attempted", which is the report's own distinction and not a
# failure of this script.
set +e
"$conformance" --scenario all --json >"$work/out" 2>"$work/err"
conformance_status=$?
set -e
[ "$conformance_status" -eq 0 ] || [ "$conformance_status" -eq 3 ] \
  || fail "the conformance tool must exit 0 or 3 (got $conformance_status)" "$work/err"
# The summary is a claim ABOUT the scenario list, so it is checked as an invariant rather than as a number:
# the two parts must agree, nothing may fail, and the count may GROW as breadth is added. A hard-coded
# `"total":17` here failed the moment the control scenarios landed, which is the same rot the conditional
# `unsupported` check below was rewritten to avoid -- a check that breaks when the work advances teaches
# people to edit the check.
summary=$(sed -n 's/.*"summary":{\([^}]*\)}.*/\1/p' "$work/out" | tail -1)
[ -n "$summary" ] || fail "the report must carry a summary" "$work/out"
summary_field() { printf '%s' "$summary" | sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p"; }
total=$(summary_field total)
passed=$(summary_field passed)
failed=$(summary_field failed)
unsupported=$(summary_field unsupported)
[ -n "$total" ] && [ -n "$passed" ] && [ -n "$failed" ] && [ -n "$unsupported" ] \
  || fail "the summary must carry all four counts" "$work/out"
[ "$failed" -eq 0 ] || fail "and no scenario may fail" "$work/out"
[ "$((passed + failed + unsupported))" -eq "$total" ] \
  || fail "the summary's counts must agree with each other" "$work/out"
listed=$(grep -o '"name":"' "$work/out" | wc -l | tr -d ' ')
[ "$listed" -eq "$total" ] \
  || fail "the summary must count what it lists (listed $listed, total $total)" "$work/out"
[ "$total" -ge 30 ] || fail "the scenario list must not shrink below thirty (got $total)" "$work/out"
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
