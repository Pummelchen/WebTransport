# Phase E — final verification (§11)

The objective is not declared complete. This file records exactly what has been verified and what has not.

## Verified

| Check | Result | Command / evidence |
| --- | --- | --- |
| Fresh clone of the audit branch | OK | `git clone --branch audit/2026-09-15 . /tmp/wt-phaseE` |
| Swift clean build (fresh clone) | exit 0, **0 warnings** | `swift build --build-tests` (`/tmp/phaseE-swift.log`) |
| Swift full suite (fresh clone) | exit 0 | `swift test` (`/tmp/phaseE-test.log`) |
| C99 configure/build (fresh clone, Ninja, Release) | exit 0 | `cmake -S C99 -B C99/out/phaseE -G Ninja` + `cmake --build` |
| C99 full suite (fresh clone) | exit 0, 97/97 | `ctest --test-dir C99/out/phaseE` |
| Swift suite on the working tree | **356 tests, 0 failures**, 0 warnings | `swift test` |
| C99 suite on the working tree | **97/97 CTest**, warnings-as-errors, ASan+UBSan leg green | `ctest` |
| Secret scan (full history, 588 commits) | no live credential; 9 test-fixture false positives allowlisted by path (one by path+exact value) | `gitleaks git --config .gitleaks.toml .` — the workflow runs it blocking |
| Dependency/misconfiguration scan | exit 0; misconfig enabled with per-file accepted DS-0002/DS-0026 | `trivy fs --config .trivy.yaml .` |
| §5 placeholder sweep | **0 real placeholders.** `TODO/FIXME/HACK/XXX/WIP/dummy/lorem` = 0 hits tree-wide; `STUB` 7 and `placeholder` 9 hits are all prose — comments explaining why a stub is *refused*, the DoD criterion that names the word, and the QUIC two-pass "placeholder tag then compute" design (crypto.h:162, server_retry.c:125-127, test_quic_connection.c:2482-2487, README:325, score-matrix.sh:72, IMPLEMENTATION_PLAN 1932/3188/3210, apps/*/main.c stub-path comments) | `grep -rIn` per marker, each hit read |
| Ledger state | 102 tasks: 98 AUDIT (fixed + verified), 3 DONE, 1 REJECTED-with-reason, **1 BLOCKED-with-owner**; no START/PROGRESS/TEST remains | `AUDIT/ledger.json` |

## Not yet verified (honest gaps)

1. **Independent host for Phase E.** The fresh-clone run above was on the machine that developed the fixes.
   `node1`, `node2` and `node4` reject our SSH key (`Permission denied (publickey,password,keyboard-interactive)`;
   `node3` is this host) and the brief (§1b) requires approval before provisioning work onto the VPS. A
   **Debian 13 container run** of the C99 leg from the same fresh clone is in flight as the closest independent
   *environment* available without a human decision (`/tmp/docker-c99.txt`); it is not a different host.
2. **Coverage numbers per language** (§1 requires coverage measurement). Both runs are in flight:
   `swift test --enable-code-coverage` + `llvm-cov report` (app+library sources, tests excluded) and a
   `--coverage` C99 build + `gcovr --gcov-executable "xcrun llvm-cov gcov"` over `C99/src` and `C99/apps`
   (`/tmp/coverage.txt`).
3. **`F-repo-ops-09` (S1, BLOCKED-with-owner)** — the third-party interop matrix predates the
   `webtransport-h3` token change; options (VPS run / release note / containerised peers only) are in the ledger.
