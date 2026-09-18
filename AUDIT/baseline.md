# AUDIT — baseline (primary host Mac14,3)

Phase A / §3. One baseline, on the primary host, committed before any fix. The language
standard in force is recorded in `AUDIT/environment.md` (standard *actually enforced*, not
intended). Every later state is compared against this table; nothing may regress without a
numbered, justified task.

| Metric | P1 Swift | P2 C99 |
| --- | --- | --- |
| Build | `swift build` — success, **0 warnings** (`.treatAllWarnings(as: .error)` in both manifests) | `C99/scripts/build-and-test.sh` — success, **0 warnings**, 0 errors (`-Werror` + the `WTCompilerWarnings.cmake` set) |
| Tests | `swift test` — **400 passed, 0 failed, 0 skipped**, exit 0 | `ctest` — **97 passed, 0 failed**, exit 0 (`100% tests passed out of 97`) |
| Coverage | **90.74% lines** (12051 lines, 1116 missed), union of the 7 test bundles, `Tests/` and `.build/` excluded | **not measured** — see below |
| Formatter | `swift format lint --strict` — clean | `clang-format` is installed but **the tree is not formatted with it and no `.clang-format` is committed** → finding (AUD-00xx) |
| Linter | `swiftlint` installed, **no committed config, not run anywhere** → finding (AUD-0006) | `cppcheck` (repo script) — clean; `scan-build` — clean (both re-run in Phase B) |
| Type checker | Swift 6 language mode (tools-version default), complete concurrency — proven in `tool-coverage.md` | `-std=c99 -pedantic-errors` equivalent (`-Wpedantic -Werror`) — proven in `tool-coverage.md` |
| Dependency CVEs | `trivy fs --config .trivy.yaml .` — **clean** (exit 0) | same scan covers the tree; the system OpenSSL is not vendored and cannot be inventoried (recorded in `SECURITY.md`) |
| Secrets | `gitleaks git --no-banner --redact --config .gitleaks.toml .` — **no leaks** in 713 commits | same |
| Python | `ruff check` — **22 findings**, no config (B/E722/S101/PT not enabled) → finding (AUD-0007) | same scripts |

## Exact commands behind the numbers

```sh
# P1
swift build
swift test                                   # 400 passed
swift test --enable-code-coverage
BINS=$(find .build/out/Products/Debug -name '*.xctest' -type d \
        | while read -r b; do find "$b" -type f -perm -111 | head -1; done)
xcrun llvm-cov report $BINS \
  -instr-profile=.build/out/Products/Debug/codecov/default.profdata \
  -ignore-filename-regex='Tests/|\.build/'
swiftlint lint --quiet --reporter summary Swift/Sources          # 317 findings, not a gate yet
ruff check $(git ls-files '*.py')                                # 22 findings, rules not enabled

# P2
C99/scripts/build-and-test.sh                # 97/97, 0 warnings

# Evidence, both projects
gitleaks git --no-banner --redact --config .gitleaks.toml .      # 713 commits, no leaks
DOCKER_CONFIG=/tmp/audit-docker-empty trivy fs --config .trivy.yaml .   # clean
```

## Deviations from CI's invocation, and why

- `trivy` needs `DOCKER_CONFIG` pointed at an empty directory on this host: the user's
  `~/.docker/config.json` names `docker-credential-desktop`, which is not installed, and
  trivy fails to fetch its vulnerability DB through it. No effect on the scanned result —
  the DB downloaded and the scan ran. Recorded so the command is reproducible.
- The coverage number excludes `Tests/`, because instrumenting the tests would inflate the
  figure without saying anything about production code.

## Gaps recorded rather than smoothed over

1. **C99 coverage is not measured.** No `gcovr`/`lcov` is installed and the C99 CMake tree
   has no coverage configuration, so a coverage % cannot be produced without adding one.
   This is recorded as a task (AUD-0009) rather than reported as "n/a"; it is a baseline
   metric the standard asks for.
2. **The two linters are installed but not in force.** `swiftlint` has no committed config
   and nothing runs it; `ruff` has no config, so the rules the Python standard names
   (B, E722, S101, PT) are not enabled. Both are findings, not baseline zeroes — a
   baseline of "0 findings" from a linter that is not running is not a baseline.
3. **The tree is not `clang-format`-clean and has no `.clang-format`.** The C standard in
   the prompt names a formatter per language. Finding, fixed in Phase B.

## Regression yardstick

Any later run may not be worse than: 0 build warnings (both), 400 Swift tests / 97 C99
tests all passing, 0 gitleaks findings, 0 trivy findings, and Swift line coverage >= 90.74%.
