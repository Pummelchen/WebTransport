#!/bin/sh
# The Clang Static Analyzer over the library (WT-176).
#
# The Definition of Done's "sanitizers and static checks are clean" criterion has been carried by the sanitizers
# and by warnings-as-errors, and the plan's Phase 13 asks for "static analysis with clang-tidy or cppcheck". This
# is the path analysis those two stand in for: the compiler's own symbolic execution over every library source,
# with the paths it cannot prove safe reported as warnings. It finds what a warning flag cannot -- a use after
# free, a null dereference on one branch, a value that is read uninitialised on a path the tests never take.
#
# The flags come from the BUILD, not from a second guess at them: the script configures a tree with
# `CMAKE_EXPORT_COMPILE_COMMANDS=ON` and replays each entry's own command with the analyzer in place of the
# compiler. Include paths, defines and the C standard are therefore the ones the library is actually compiled
# with, which is the difference between analyzing this code and analyzing something like it.
#
# Usage: check-static-analysis.sh [analyzer] [build-dir]
#   analyzer   the clang to run (default: clang, which must be one that has --analyze)
#   build-dir  where the compile-commands tree is configured (default: out/analyze)
set -eu

analyzer="${1:-clang}"
build="${2:-out/analyze}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A machine without the analyzer reports that, the way the Windows checks report a missing cross-compiler: the
# check is skipped with its reason rather than failing a build for a tool that is not installed. Where clang IS
# present -- every macOS runner, and any Linux runner with it -- a finding fails the job, which is the point.
# The status is 77 -- CTest's skip code, and a NON-PASSING status for a plain CI step -- because `exit 0` made
# "the check could not run" indistinguishable from "the check ran and found nothing", which is the one thing a
# hard check must not do.
if ! "$analyzer" --analyze -x c /dev/null -o /dev/null >/dev/null 2>&1; then
  echo "static analysis: unsupported -- $analyzer has no --analyze, so this machine cannot check the paths"
  exit 77
fi

# The analysis is driven by python3, which reads the compilation database and replays each entry with the analyzer
# in place of the compiler. A machine without it cannot check a path, and says so rather than reporting success
# (WT-201). Status 77 for the reason above.
if ! command -v python3 >/dev/null 2>&1; then
  echo "static analysis: unsupported -- python3 is not installed, so the compilation database cannot be replayed"
  exit 77
fi

(cd "$root" && cmake -S . -B "$build" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug >/dev/null)

# One analysis per SOURCE, not per build entry: the static and shared libraries compile the same file twice
# with the same flags, and analysing it twice adds nothing.
python3 - "$root/$build/compile_commands.json" "$analyzer" "$work" "$root" <<'ANALYZE'
import json, os, shlex, subprocess, sys

database, analyzer, work, root = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
entries = json.load(open(database))
seen = {}
for entry in entries:
    path = entry["file"]
    # The library AND the tools: the tools are what a caller runs, and a null dereference in a listener's argument
    # parsing is as real as one in a parser. The tests are left out -- they are not shipped, and their job is to
    # do things the library must survive rather than to be models of defensive code.
    if "/src/" not in path and "/apps/" not in path:
        continue
    if path in seen:
        continue
    seen[path] = entry

if not seen:
    sys.stderr.write("static analysis: no sources in the compile database\n")
    sys.exit(1)

# The command the build used, with the analyzer in place of the compiler. The dependency-generation flags go
# (they write files nobody reads here) and the object output goes (the analyzer writes its findings to stderr),
# but every include path, define and warning flag stays.
def analyzer_command(command, path):
    words = shlex.split(command)
    out = [analyzer, "--analyze", "-Xanalyzer", "-analyzer-output=text"]
    skip = False
    for word in words[1:]:
        if skip:
            skip = False
            continue
        if word in ("-o", "-MF", "-MT", "-MQ"):
            skip = True
            continue
        if word in ("-MD", "-MMD", "-MP", "-c"):
            continue
        # `-c` goes: with `--analyze` clang has no use for it and says so as an unused argument, which the
        # build's `-Werror` turns into a refusal -- and a REFUSED command has no "warning:" line in it, so the
        # check reported a clean tree it had never analyzed. The source operand is the only thing needed.
        # The source operand appears in the command AND is appended here; keeping both would hand clang two
        # translation units, which it refuses rather than analyzes -- and a refused command has no "warning:" line
        # in it, so the check reported a clean tree it had never looked at.
        if word == path:
            continue
        out.append(word)
    out.append(path)
    return out

findings = []
refused = []
analyzed = 0
verbose = os.environ.get("STATIC_ANALYSIS_VERBOSE") is not None
for path in sorted(seen):
    command = analyzer_command(seen[path]["command"], path)
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    analyzed += 1
    if verbose:
        print("  " + " ".join(shlex.quote(word) for word in command), file=sys.stderr)
    text = result.stdout + result.stderr
    if verbose:
        sys.stderr.write(text)
    for line in text.splitlines():
        if "warning:" in line:
            findings.append(line.strip())
    # A non-zero exit with no warning is the analyzer REFUSING to run -- a flag it did not like, a missing
    # include -- and reporting that as "no findings" is the one failure mode this check must not have. The
    # `-c`/`-Werror` interaction above did exactly that on every file.
    if result.returncode != 0 and "warning:" not in text:
        refused.append((path, text.strip().splitlines()[:3]))

print(f"static analysis: {analyzed} source(s) analyzed")
for path, lines in refused:
    print(f"  the analyzer refused {os.path.relpath(path, root)}:")
    for line in lines:
        print("    " + line)
for finding in findings:
    print("  " + finding)
if findings or refused:
    sys.exit(1)
print("static analysis: no findings")
ANALYZE
