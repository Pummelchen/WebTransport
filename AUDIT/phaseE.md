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
   `node3` is this host) and the brief (§1b) requires approval before provisioning work onto the VPS. **Debian 13 container run: DONE** — from a fresh clone at `/Users/node3/Downloads/wt-phaseE-clone`, inside
   `debian:trixie` with system GCC 14.2 and system OpenSSL 3, no host toolchain: configure, build and
   `100% tests passed, 0 tests failed out of 97` (`docker job exit=0`). This is an independent *environment*,
   not an independent host — the host requirement of §12 is still the open decision below.
   **Swift on Linux: MEASURED, not assumed** (`F-repo-ops-20`). The VPS now carries signature-verified
   Swift 6.4.0 for Debian 13 (`/opt/swift-toolchains/swift-6.4`, install block in `AUDIT/environment.md`), so
   "the Swift tree cannot run on Linux" is no longer an untested sentence: of the 11 library targets, exactly
   `WebTransportQUICCore` and `WebTransportHTTP3Core` build there (0 warnings, warnings-as-errors and strict
   memory safety on), and the other nine fail on a named Apple module — `Darwin`
   (`WebTransportUDPApple`, `WebTransportLoopbackTestSupport`), `CryptoKit` (`WebTransportCryptoApple`,
   `WebTransportTLSCore`, `WebTransportTestSupport`) or `CoreFoundation` through the C shim header
   (`WebTransportSecurityShim`, and with it `WebTransport`, `WebTransportNetworkRuntime`,
   `WebTransportCLIConformance`). The shipped product therefore still has no Linux Swift leg and the
   independent-host requirement for the Swift side remains unmet — but it is now a bounded measurement with
   logs (`/var/wt-swift-linux-probe/out/`), not a blanket claim.
2. **Coverage numbers per language** (§1 requires coverage measurement). **Swift: DONE** — 85.88% line, 95.97% function, 93.06% region over 1,409 non-test lines (`swift test --enable-code-coverage` + `xcrun llvm-cov report` over every `.xctest` binary, tests and `.build` excluded).
   **C99: in flight** — a `--coverage` build and `gcovr` over **C99: DONE** — **90.9% line (12,986/14,292), 99.2% function (1,042/1,050), 67.3% branch (8,222/12,213)** over `C99/src` and
   `C99/apps`, measured with `gcovr` inside the Debian 13 container from the fresh clone. Two earlier attempts reported
   `0.0% (0 out of 0)`, which is not a measurement: the first filtered on `C99/`-prefixed paths against a `-r C99` root and
   the second kept the wrong root; the working invocation roots gcovr at the BUILD directory and filters absolute paths.
3. **`F-repo-ops-09` (S1, BLOCKED-with-owner)** — the third-party interop matrix predates the
   `webtransport-h3` token change; options (VPS run / release note / containerised peers only) are in the ledger.

## Phase E — final state (round 12)

| Requirement (§12) | Evidence |
| --- | --- |
| Clean build, zero warnings, from a fresh checkout | Swift (macOS 26, Xcode 27): fresh clone, `Build complete!`, **0 warnings**, `swift test` **356/356**. C99 (VPS Debian 13, gcc 14.2, its own toolchain): fresh tree, 0 warnings, **97/97 CTest**. C99 again in `debian:trixie` (system GCC/OpenSSL): **97/97**. |
| Independent host | **VPS Debian 13** for the C99 leg (a host that did not develop the fixes). For Swift the same host now runs the mandated Swift 6.4 and the boundary is **measured**: exactly 2 of 11 library targets build there (`F-repo-ops-20`, `AUDIT/environment.md`), the rest need `Darwin`, `CryptoKit` or `CoreFoundation`, so the Swift product has no Linux leg and its independent evidence remains the macOS fresh clone plus the two CI legs. The 4-Mac fleet still rejects our SSH key, which is recorded rather than papered over. |
| Coverage | Swift **85.88% line / 95.97% function / 93.06% region**; C99 **90.9% line / 99.2% function / 67.3% branch**. |
| Scanners clean or waived in writing | gitleaks over the full history (588 commits): no live credential, 9 test-fixture false positives allowlisted by path (one by path + exact value). trivy: exit 0, `misconfig` enabled with per-file accepted DS-0002/DS-0026 and the system-OpenSSL decision written in `SECURITY.md`. |
| Zero placeholders | §5 sweep: `TODO/FIXME/HACK/XXX/WIP/dummy/lorem` = 0; every `STUB`/`placeholder` hit read as prose. |
| Ledger: no non-BLOCKED open task | 106 entries: 97 AUDIT (fixed + verified), 9 DONE (one of them, `F-swift-line-security-05b`, was first rejected with a recorded measurement and then implemented at the owner's request), 0 open, 0 blocked. |
| Wiki synced | `Project-Tracker.md` mirrors this outcome; the ledger wins on conflict. |

The interop criterion is verified **with the per-peer token selection documented**: 7 of 7 proofs across 5 implementations,
every proof on attempt 1, in two independent VPS runs (`vps-interop-f02b-run{1,2}`), after `F-02b` gave the client an
explicit `--upgrade-token draft16|legacy` (draft-16 default) instead of reverting the draft-16 change.
