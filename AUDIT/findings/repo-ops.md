# repo-ops — L0 repository level + L7 ops + §5 placeholder sweep + §6 unused-code rule

Branch `audit/2026-09-15`, base `196324e`. Read-only pass; the only files written are this one and
`AUDIT/findings/repo-ops.json`.

Scope: the whole repository, excluding the `.build/` and `C99/out/` build trees but including everything
git tracks. Commands run for evidence (all read-only or build-sandbox only): `git ls-files`, `git grep`,
`gitleaks git`, `trufflehog git --only-verified`, `trivy fs`, `ctest --test-dir C99/out/macos26/build`
(97/97), `swift test` (308), `python3 C99/scripts/check-workflows.py`, `nm` over the built C99 archive,
and the two built CLI binaries.

---

## Findings

### F-repo-ops-01 — S1 / test — CI never builds or tests on the mandated Swift 6.4 / Xcode 27 toolchain

`file:line`: `.github/workflows/swift-ci.yml:15-21` (job `macos-swift`, `runs-on: macos-26`),
`Swift/check-toolchain.sh:4-5`

**What is wrong.** The deliverable is built and audited on Swift 6.4 / Xcode 27 (`swift --version` here:
`Apple Swift version 6.4 (swiftlang-6.4.0.34.1)`, `Xcode 27.0 (27A266a)`). CI selects no toolchain at all —
there is no `xcode-select`, `DEVELOPER_DIR`, `setup-xcode` or `Xcode_*` step — so it uses whatever Xcode the
`macos-26` image happens to ship (Xcode 26.x / Swift 6.3.x, consistent with the job name "Swift 6.3.3+").
`check-toolchain.sh` only enforces a *minimum* of 6.3.3 / 26.6, so a 6.3 runner passes the gate. A
Swift-6.4-only failure is therefore invisible to CI, and the baseline proves that it happened.

**Evidence.**

```
$ grep -niE 'xcode-select|DEVELOPER_DIR|setup-xcode|maxim-lobanov|Xcode' .github/workflows/swift-ci.yml
NO Xcode/toolchain selection step in swift-ci.yml

$ grep -n 'minimum_swift\|minimum_xcode' Swift/check-toolchain.sh
4:minimum_swift="6.3.3"
5:minimum_xcode="26.6"

$ swift --version          # the mandated toolchain
Apple Swift version 6.4 (swiftlang-6.4.0.34.1)
$ xcodebuild -version
Xcode 27.0 / Build version 27A266a

AUDIT/baseline.md:10-13 — on Swift 6.4 the root manifest build FAILED (linker: undefined
WebTransportTLSCore.TLSExtension.decodeList, …), so `swift test` could not run at all, while CI was green.
```

**What correct looks like.** The toolchain the mandate names is the toolchain CI runs, so the class of defect
the audit found at baseline (A-0001) fails a PR instead of reaching `main`. Related, already on the ledger:
A-0005 (`swift-tools-version: 6.3` vs the mandated 6.4).

**Smallest correct fix.** Add a toolchain-selection step to the `macos-swift` job (e.g.
`sudo xcode-select -s /Applications/Xcode_27.app` or `maxim-lobanov/setup-xcode` with `xcode-version: '27.0'`)
and raise `minimum_swift`/`minimum_xcode` in `Swift/check-toolchain.sh` to `6.4`/`27.0`. If 6.3.3 really is the
supported floor, add a second matrix leg pinned to Xcode 27 so both are exercised.

---

### F-repo-ops-02 — S2 / deps — 185 files of CMake/Ninja build output are committed at the repository root

`file:line`: `build/CMakeCache.txt:391` (and the tracked `build/` directory, 185 files, 4.1 MB)

**What is wrong.** `build/` is tracked and contains object files, static/shared libraries, executables, the
Ninja database, the CMake cache, and the previous run's ctest state — including a stale
`build/Testing/Temporary/LastTestsFailed.log` that records `test_quic_connection` as failed (it passes today).
`.gitignore` ignores `.build/`, `Swift/.build/` and `.webtransport-cli-logs/` but not `build/`. The committed
CMake cache points at a different checkout and the committed configure log leaks the author's home directory,
so this is also a machine-specific artifact.

**Evidence.**

```
$ git ls-files build | wc -l
185
$ git ls-files build | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -3
113 o
 11 cmake
  3 dylib
$ du -sh build
4.1M	build
$ git check-ignore -v build/CMakeCache.txt
NOT IGNORED: build/
$ grep -n 'CMAKE_HOME_DIRECTORY' build/CMakeCache.txt
391:CMAKE_HOME_DIRECTORY:INTERNAL=/tmp/wt-clone/C99
$ grep -n '/Users/andreborchert' build/CMakeFiles/CMakeConfigureLog.yaml | head -2
23:      - "/Users/andreborchert/Library/CloudStorage/Dropbox/Coding/DeepSeek/…"
24:      - "/Users/andreborchert/.cache/node/corepack/v1/pnpm/11.7.0/dist/node-gyp-bin/"
$ cat build/Testing/Temporary/LastTestsFailed.log
26:test_quic_connection
$ ctest --test-dir C99/out/macos26/build     # today
100% tests passed out of 97
```

No script, document or workflow reads this directory: `git grep -nE '(^|[^/])build/(CMakeCache|build\.ninja|tests|apps)' --
'*.sh' '*.md' '*.py' '*.yml'` returns nothing, and the C99 scripts all work under `C99/out/`. (Ledger A-0002
already records this class.)

**What correct looks like.** The repository tracks sources, not one machine's build tree: `build/` is ignored
and untracked, and adding `build/` to `.gitignore` stops it coming back. The build directory is
`C99/out/<platform>/…` as `C99/scripts/build-and-test.sh` documents.

**Smallest correct fix.** `git rm -r --cached build && printf 'build/\n' >> .gitignore`. (History rewrite is a
separate decision; at minimum stop tracking new output.) Note the leaked home paths identify a person but are
not credentials.

---

### F-repo-ops-03 — S2 / docs — README says GitHub provides no Windows runner and that the Windows CI job is missing; the workflow runs one on `windows-latest`

`file:line`: `README.md:51-55` vs `.github/workflows/c99-ci.yml:261-263`

**What is wrong.** The README's status paragraph says the tree runs "on two platforms GitHub provides no runner
for -- Windows … and FreeBSD 15.1", and that the one partial completion criterion is "the CI *job* for the
Windows and FreeBSD legs". GitHub does provide Windows runners, and this repository already uses one: the
`windows-native` job runs `runs-on: windows-latest` with MSYS2. Only the FreeBSD leg is genuinely absent
(the workflow header at `c99-ci.yml:5-8` says so). A reader is told a platform is un-CI-able when CI already
covers it, and told the Windows job does not exist when it does (it exists but is `continue-on-error: true`).

**Evidence.**

```
README.md:51-55:
  The tree also compiles, links and **runs** on two platforms GitHub provides no runner
  for -- Windows (85 of 85 test executables under Wine, …) and FreeBSD 15.1 (…). Of the plan's
  nine completion criteria **8 are met and 1 is partial** (the CI *job* for the Windows and FreeBSD legs,
  not the code on them).

.github/workflows/c99-ci.yml:261-267:
  windows-native:
    name: C99 / Windows (native, MSYS2 MINGW64)
    runs-on: windows-latest
    continue-on-error: true
.github/workflows/c99-ci.yml:5-8:
  # … the FreeBSD leg is still to be added; and the Windows leg is here twice …
```

**What correct looks like.** The status paragraph distinguishes the two claims: Windows is covered by two CI
legs (one enforced, one not yet enforced), and only FreeBSD lacks a CI job / hosted runner.

**Smallest correct fix.** Rewrite `README.md:51-55` (and the matching sentence in `C99/README.md:24`) to say
"FreeBSD 15.1 has no CI leg; the native Windows job exists but is not yet enforced". Matching the ledger's
"1 partial" wording to reality is a one-paragraph edit.

---

### F-repo-ops-04 — S2 / docs — the documented "Debian 13" CI platform is actually `ubuntu-24.04`; the workflow's own header claims Debian

`file:line`: `C99/README.md:23`, `README.md:50-51`, `.github/workflows/c99-ci.yml:5-8` and `:46-51`

**What is wrong.** Both READMEs and the workflow's opening comment state that the C99 suite runs (green) on
Debian 13. The matrix is `macos-26` plus two `ubuntu-24.04` legs; there is no Debian leg. The
`IMPLEMENTATION_PLAN.md:2933-2934` names "Debian 13, GCC" and "Debian 13, Clang" as the intended legs, so the
documented platform is the plan's, not the workflow's. Ubuntu 24.04 is glibc 2.39 / Debian-derived, which is a
different portability claim from Debian 13 (trixie).

**Evidence.**

```
$ git grep -n 'Debian 13' -- README.md C99 .github
C99/README.md:23:**97 CTest tests pass on macOS 26 and on Debian 13**, and the tree also runs on two platforms
README.md:51:Debian 13**. The tree also compiles, links and **runs** …
$ git grep -ni 'ubuntu' -- .github/workflows/c99-ci.yml
48:          - os: ubuntu-24.04
50:          - os: ubuntu-24.04
215:    runs-on: ubuntu-24.04
$ sed -n '5,8p' .github/workflows/c99-ci.yml
# … macOS 26 and Debian
# run the tree in CI as they always have; the FreeBSD leg is still to be added; …
```

**What correct looks like.** Either the CI leg is Debian 13 (a `container: debian:13` job, as the plan asks) or
the READMEs and the workflow comment say Ubuntu 24.04. The two must not disagree.

**Smallest correct fix.** Change the two README sentences to "Ubuntu 24.04" if that is the shipping platform,
or add `container: debian:trixie` to the Linux matrix legs. One line either way.

---

### F-repo-ops-05 — S2 / docs — `SECURITY.md` supported-versions table names `1.1.x` and omits the current `1.3.x` line

`file:line`: `SECURITY.md:7-13`

**What is wrong.** The security policy promises fixes "for the current `main` branch and the latest tagged
release line", and its table marks `main` Yes, `1.1.x` Yes, earlier No. The latest tag is `1.3.8`
(`git tag` confirms 1.0.0 … 1.3.8), and the README's install snippet pins `1.3.8`. A customer reading the
policy cannot tell whether the release they run is supported — the table answers for a line eight releases
old and says nothing about 1.3.x.

**Evidence.**

```
SECURITY.md:7-13:
  | Version | Supported |
  | `main`  | Yes       |
  | `1.1.x` | Yes       |
  | Earlier releases | No |
$ git tag | tail -3
1.3.6
1.3.7
1.3.8
$ grep -n 'exact:' README.md
127:    exact: "1.3.8"
```

**What correct looks like.** The table names the current release line (`1.3.x`) and drops `1.1.x` unless fixes
are actually still being issued for it.

**Smallest correct fix.** Change `| 1.1.x | Yes |` to `| 1.3.x | Yes |` (and add `1.1.x` under "Earlier
releases" if it is no longer supported).

---

### F-repo-ops-06 — S2 / test — no secret or dependency/CVE scanning in either workflow, and no scanner configuration for the committed test keys

`file:line`: `.github/workflows/swift-ci.yml:14-119`, `.github/workflows/c99-ci.yml:38-330`

**What is wrong.** The repository ships a public security-sensitive library, and CI gates formatting, static
analysis, sanitizers and fuzzing — but nothing scans commits for credentials and nothing scans the tree for
known-vulnerable dependencies. There is also no `.gitleaks.toml`/trufflehog config, so the intentional
test-only private keys under `C99/tests/vectors/trust/` (documented as fixtures in that directory's README)
would surface as unexplained hits the moment a scanner is switched on. This is the "checker nothing runs"
gap the project already recognises for its own scripts (`c99-ci.yml:56-59`).

**Evidence.**

```
$ grep -niE 'gitleaks|trufflehog|trivy|secret|audit|dependabot|scorecard' .github/workflows/*.yml
NO secret/CVE scanning step in either workflow
$ git ls-files | grep -iE 'gitleaks|trufflehog|secret|dependabot|renovate'
NONE tracked
```

Scanner results over the full history (counts only; see "Scanner runs" below): gitleaks 9 findings over 503
commits, trufflehog 0 verified / 0 unverified, trivy 0 vulnerabilities, 12 misconfigurations, 0 secrets.
No live-looking credential was found; the 3 gitleaks `private-key` hits are the documented fixtures.

**What correct looks like.** A CI job runs the secret scanner on every PR (with a narrow allowlist for the
fixture directory and a comment saying why), and the C99/Swift dependency surface (system OpenSSL) is
covered by a vulnerability scan or an explicit, written decision not to.

**Smallest correct fix.** Add a `secret-scan` job running `gitleaks detect` (or the repo's local
`gitleaks git`) with a `.gitleaks.toml` allowing `C99/tests/vectors/trust/` by path and rule. Pin the tool
version to the one recorded in `AUDIT/environment.md`.

---

### F-repo-ops-07 — S2 / placeholder — the default `WebTransportServer` invocation prints "local demo endpoint ready" and exits 0 without binding anything

`file:line`: `Swift/Sources/WebTransportServer/main.swift:95-103`

**What is wrong.** Run with no arguments, the shipped server binary constructs a `WebTransportServer` value and
immediately discards it (`_ = WebTransportServer(configuration: configuration)`), then prints
"WebTransportServer local demo endpoint ready: authority=localhost path=/wt" and exits 0.
`WebTransportServer.init` only stores the configuration (`Swift/Sources/WebTransport/WebTransport.swift:429-433`);
it does not listen. A readiness message that is not true, on the default path of a released binary, is exactly
the "hardcoded success / surface wired to nothing" §5 asks for — a supervisor or a health probe that keys on
exit status reads it as a running endpoint.

**Evidence.**

```
$ .build/arm64-apple-macosx/debug/WebTransportServer     # no arguments
WebTransportServer local demo endpoint ready: authority=localhost path=/wt
Use `swift run WebTransportClient --connect HOST:PORT` with a listening server for the Network.framework QUIC session path.
exit=0

Swift/Sources/WebTransport/WebTransport.swift:429-433:
  public init(configuration: WebTransportServerConfiguration, logger: WebTransportLogger = .disabled) {
      self.configuration = configuration
      self.logger = logger
  }
  /// Starts a network listener. The returned server owns the underlying …
```

**What correct looks like.** The no-argument path either actually listens (`--listen` is the real path and
`listen()`/`waitForListening` exists) or it says what it is — for example "no listener started; pass
`--listen host:port`" — without the word "ready" and without exit 0 masquerading as a served endpoint.

**Smallest correct fix.** Replace the message at `main.swift:102` with a line that names the missing argument
and print the usage text; the second printed line already says a listening server is elsewhere.

---

### F-repo-ops-08 — S2 / dead — three exported C99 functions have no caller and no test anywhere in the tree (SUSPECTED)

`file:line`: `C99/include/webtransport/quic/connection.h:933` (`wt_quic_space_name`),
`C99/include/webtransport/tls/handshake.h:166` (`wt_tls_encrypted_extensions_build`),
`C99/include/webtransport/tls/handshake.h:233` (`wt_tls_certificate_verify_build`)

**What is wrong.** Each of these names occurs exactly twice in the whole `C99/` tree — its declaration and its
definition. Reachability proof performed (not a grep alone): (1) all files under `C99/` except `C99/out/` were
read and every occurrence counted, so no test, app, script or other source calls them; (2) C has no reflection,
no registry and no string-keyed dispatch, and the name-function family is called directly (its siblings
`wt_quic_frame_kind_name` and `wt_quic_packet_type_name` are called from `C99/tests/unit/test_quic_frame.c`
and `test_quic_packet.c`), so there is no dynamic-dispatch path that could hide a caller; (3) they are not
referenced by `.github/`, CMake, or any script; (4) the installed public headers export them, which is the one
legitimate reason to keep an uncalled function — hence SUSPECTED, not CONFIRMED-dead.

**Evidence.**

```
$ git grep -n --fixed-strings wt_quic_space_name -- C99 ':!C99/out'
C99/include/webtransport/quic/connection.h:933:const char *wt_quic_space_name(wt_quic_space_t space);
C99/src/quic/connection.c:49:const char *wt_quic_space_name(wt_quic_space_t space) {
$ git grep -n --fixed-strings wt_tls_certificate_verify_build -- C99 ':!C99/out'
C99/include/webtransport/tls/handshake.h:233:wt_status_t wt_tls_certificate_verify_build(uint16_t scheme,
C99/src/tls/handshake.c:739:wt_status_t wt_tls_certificate_verify_build(uint16_t scheme,
$ git grep -n --fixed-strings wt_tls_encrypted_extensions_build -- C99 ':!C99/out'
C99/include/webtransport/tls/handshake.h:166:wt_status_t wt_tls_encrypted_extensions_build(
C99/src/tls/handshake.c:888:wt_status_t wt_tls_encrypted_extensions_build(
(nm -gU over build/libwebtransport.a: all three are defined and exported)
```

**What correct looks like.** Either the functions are part of the intended public surface and have a test that
exercises them (as their siblings do), or they are internal and lose their header declarations, or they are
deleted. The C99 plan's own completion criterion says no unused surface is exposed as production.

**Smallest correct fix.** Add one assertion each to the existing unit suites (`test_quic_connection.c` for the
space name, `test_tls13_handshake.c` for the two builders) or remove the three declarations and definitions.
Choose one; leaving an untested, uncalled export is the only wrong outcome.

---

### F-repo-ops-09 — S3 / docs — the documented C99 check count (91,552) does not reproduce; the measured count is 91,713

`file:line`: `C99/README.md:61`, `README.md:48`

**What is wrong.** Both READMEs state "84 test programs and 91,552 checks". On this host the suite runs exactly
84 programs but 91,713 checks. The program count is right; the check count is stale by 161. `AUDIT/baseline.md:29`
propagated the README figure rather than measuring it, so the number is now quoted in three places.

**Evidence.**

```
$ ctest --test-dir C99/out/macos26/build -V > /tmp/ctestv.txt
$ grep -oE '[A-Za-z0-9_]+: all [0-9]+ checks passed' /tmp/ctestv.txt | awk '{s+=$3} END{print s}'
91713
$ ... | wc -l        # programs
84
$ ctest --test-dir C99/out/macos26/build | tail -2
100% tests passed out of 97
Total Test time (real) =  19.14 sec
$ git grep -n '91,552' -- . ':!build' ':!C99/out'
C99/README.md:61:  - 84 test programs and 91,552 checks, plus a 200,000-input parser fuzz run, …
README.md:48:84 test programs and 91,552 checks pass (plus a 200,000-input parser fuzz run …
```

**What correct looks like.** A measured number in the README is the number the suite prints, or the sentence
drops the exact figure and says "over 91,000 checks".

**Smallest correct fix.** Re-measure and update the two README lines (and `AUDIT/baseline.md`, or leave the
audit artifact as a snapshot). Better: make `C99/scripts/score-matrix.sh` print the check total so the number
is derived rather than remembered.

---

### F-repo-ops-10 — S3 / docs — three C99 CLI mains still describe the Phase-0 stub that "prints its usage and exits 3"

`file:line`: `C99/apps/wt-client-c99/main.c:1-8`, `C99/apps/wt-server-c99/main.c:1-8`,
`C99/apps/wt-conformance-c99/main.c:1-8`

**What is wrong.** All three file headers say the tool exists as a Phase-0 stub, that the protocol phases will
fill it in, and that "until they do the tool prints its usage and exits 3". The tools are implemented (Phase 9
complete, per the same tree's README) and behave differently: with no arguments each exits **2** printing an
error, and `--help` exits **0**. The comment is the first thing a reader of the file sees and it is false.

**Evidence.**

```
$ C99/out/macos26/build/apps/wt-client-c99 ; echo "exit=$?"
wt: no address: pass host:port
exit=2
$ C99/out/macos26/build/apps/wt-client-c99 --help >/dev/null ; echo "exit=$?"
exit=0
$ C99/out/macos26/build/apps/wt-server-c99 ; echo "exit=$?"
wt: no address: pass host:port
exit=2
$ sed -n '1,7p' C99/apps/wt-client-c99/main.c
/* wt-client-c99 -- see ../../IMPLEMENTATION_PLAN.md, Phase 9.
 *
 * Phase 0 builds the executable and its link against the library, …
 * the tool prints its usage and exits 3 -- a distinct status for "not
 * implemented" so that a script driving it cannot read a stub as success.
 */
```

**What correct looks like.** The header describes the tool that is there: what it does, its exit statuses
(`0` success, `1` scenario failure, `2` argument error, `3` nothing failed but something was not attempted).

**Smallest correct fix.** Replace the Phase-0 paragraph in the three headers with one sentence naming the
current contract (the `--help` text already lists the options and statuses).

---

### F-repo-ops-11 — S3 / docs — the fuzz test says "CI uses the default", but CI sets a 20,000-iteration budget

`file:line`: `Swift/Tests/WebTransportHTTP3CoreTests/PeerInputFuzzTests.swift:21-23` vs
`.github/workflows/swift-ci.yml:96-101`

**What is wrong.** The comment above the iteration budget says the environment variable "raises the per-parser
budget for longer local runs; CI uses the default." The `fuzz-peer-input` job exports
`WEBTRANSPORT_FUZZ_ITERATIONS: "20000"`, 50× the code default of 400. The comment inverts which side is the
larger run, which is the opposite of what a reader needs when judging how much fuzzing CI actually does.

**Evidence.**

```
Swift/Tests/WebTransportHTTP3CoreTests/PeerInputFuzzTests.swift:21-23:
  // … `WEBTRANSPORT_FUZZ_ITERATIONS` raises the per-parser budget for
  // longer local runs; CI uses the default.
Swift/Tests/WebTransportHTTP3CoreTests/PeerInputFuzzTests.swift:140-147:
  if let raw = ProcessInfo.processInfo.environment["WEBTRANSPORT_FUZZ_ITERATIONS"], … { return parsed }
  return 400
.github/workflows/swift-ci.yml:96-101:
  - name: Fuzz under AddressSanitizer
    env:
      WEBTRANSPORT_FUZZ_ITERATIONS: "20000"
    run: >- swift test --sanitize=address --filter 'peerFacingParsers|huffmanDecoder'
```

**What correct looks like.** The comment says CI raises the budget to 20,000 and the default is for a local
`swift test`.

**Smallest correct fix.** Reword the two comment lines.

---

### F-repo-ops-12 — S3 / deps — neither workflow declares `permissions:`, and every action is pinned to a mutable tag

`file:line`: `.github/workflows/swift-ci.yml:1-14`, `.github/workflows/c99-ci.yml:1-36`;
uses at `swift-ci.yml:21,90,108` and `c99-ci.yml:54,218,273,276`

**What is wrong.** Two supply-chain hygiene gaps in the release gate. (1) No `permissions:` key, so each job
gets the repository default token scope; least privilege would be `contents: read` for jobs that only check out
and build. (2) Third-party actions are referenced by moving tags (`actions/checkout@v6`,
`msys2/setup-msys2@v2`), so the code CI executes can change without a commit in this repository — the same
"the job does not move under the project's feet" principle the workflow already applies to the MSYS2 OpenSSL
package (`c99-ci.yml:170-183`).

**Evidence.**

```
$ grep -n 'permissions' .github/workflows/*.yml
NO permissions: key in either workflow
$ grep -nE 'uses:' .github/workflows/*.yml
.github/workflows/c99-ci.yml:54:        uses: actions/checkout@v6
.github/workflows/c99-ci.yml:218:        uses: actions/checkout@v6
.github/workflows/c99-ci.yml:273:        uses: actions/checkout@v6
.github/workflows/c99-ci.yml:276:        uses: msys2/setup-msys2@v2
.github/workflows/swift-ci.yml:21:        uses: actions/checkout@v6
.github/workflows/swift-ci.yml:90:        uses: actions/checkout@v6
.github/workflows/swift-ci.yml:108:        uses: actions/checkout@v6
```

**What correct looks like.** `permissions: contents: read` at workflow (or job) level, and actions pinned to
full commit SHAs with the version in a trailing comment.

**Smallest correct fix.** Add `permissions:\n  contents: read` above `jobs:` in both files; replace each tag
with the SHA it currently resolves to (Dependabot, if enabled, can keep the comments current).

---

### F-repo-ops-13 — S3 / test — the six interop Docker images run as root and declare no health check

`file:line`: `C99/tests/interop/client/Dockerfile:11`, `C99/tests/interop/peer/Dockerfile:6`,
`C99/tests/interop/peer/Dockerfile.aioquic:2`, `Swift/interop-docker/pywebtransport/Dockerfile:1`,
`Swift/interop-docker/quiche/Dockerfile:1`, `Swift/interop-docker/quinn/Dockerfile:1`

**What is wrong.** `trivy fs` reports the same two misconfigurations for every Dockerfile: DS-0002 (HIGH) no
non-root `USER`, DS-0026 (LOW) no `HEALTHCHECK`. These are interop *test* containers, not shipped images, so
the practical risk is low — but the repository has no stated policy that says so, and the report will keep
appearing in every scan.

**Evidence.**

```
$ trivy fs --scanners vuln,secret,misconfig .     # summary table
| C99/tests/interop/client/Dockerfile            | dockerfile | - | - | 2 |
| C99/tests/interop/peer/Dockerfile              | dockerfile | - | - | 2 |
| C99/tests/interop/peer/Dockerfile.aioquic      | dockerfile | - | - | 2 |
| Swift/interop-docker/pywebtransport/Dockerfile | dockerfile | - | - | 2 |
| Swift/interop-docker/quiche/Dockerfile         | dockerfile | - | - | 2 |
| Swift/interop-docker/quinn/Dockerfile          | dockerfile | - | - | 2 |
Failures: 2 per image (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 1, CRITICAL: 0)  → 6 HIGH + 6 LOW
DS-0002 (HIGH): Specify at least 1 USER command in Dockerfile with non-root user as argument
DS-0026 (LOW):  Add HEALTHCHECK instruction in your Dockerfile
```

**What correct looks like.** Either the test images add a non-root `USER` (they only compile and run local
interop peers), or a scan policy records them as accepted with the reason. Nothing in the tree records the
decision today.

**Smallest correct fix.** Add `USER 1000:1000` to the test Dockerfiles where the image does not need to write
outside its work dir, and suppress DS-0026 for these test-only images in the scan configuration once one exists
(see F-repo-ops-06).

---

### F-repo-ops-14 — S3 / deps — `.github/traffic.json` is generated badge data committed to the repository and never regenerated

`file:line`: `.github/traffic.json:1-6`, consumed at `README.md:11`

**What is wrong.** The README's "Views (14d)" badge fetches `.github/traffic.json` from `main`. That file is a
snapshot (`"message": "18"`) with no producer in the repository: no workflow, script or hook writes it, and the
two workflows do not reference it. A committed generated file with a stale measurement reads as live data.

**Evidence.**

```
$ cat .github/traffic.json
{ "schemaVersion": 1, "label": "Views (14d)", "message": "18", "color": "blueviolet" }
$ git grep -n 'traffic.json' -- . ':!build' ':!C99/out'
README.md:11:[![Views (14d)](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/…/main/.github/traffic.json)]…
```

**What correct looks like.** Either a scheduled workflow refreshes the file (and the commit is automated), or
the badge is dropped, or the file's header states it is refreshed by hand and when.

**Smallest correct fix.** Add a scheduled workflow that regenerates `traffic.json` from the traffic API, or
remove the badge and the file.

---

### F-repo-ops-15 — S3 / incomplete — `--timeout-ms` is unvalidated in the Swift server CLI while the C99 CLI rejects the same value

`file:line`: `Swift/Sources/WebTransportServer/main.swift:165-170` vs `C99/src/cli/options.c:220-221`

**What is wrong.** `NetworkServerOptions.parse` accepts any `Int32` for `--timeout-ms` — including `0` and
negative values — and passes it straight to `waitForListening`/`serveOne`. The C99 CLI validates the same
switch at parse time and rejects zero with "a zero timeout would wait forever". In Swift a bad value is not
diagnosed at startup: `InteroperableQUICHelpers.withTimeout` throws
`WebTransportNetworkRuntimeError.timeout(0)` (`WebTransportInteroperableNetworkRuntime.swift:1946-1952`), so an
operator sees a timeout rather than an argument error. (Other startup validation in this parser is good:
`--max-sessions` is range-checked at `main.swift:177-186`, `--path` must start with `/`.)

**Evidence.**

```
Swift/Sources/WebTransportServer/main.swift:165-170:
  case "--timeout-ms":
      index += 1
      guard index < arguments.count, let value = Int32(arguments[index]) else { … }
      timeoutMilliseconds = value
C99/src/cli/options.c:220-221:
  if (options->timeout_ms == 0U) {
    if (out_error != NULL) *out_error = "a zero timeout would wait forever";
Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1950-1952:
  guard timeoutMilliseconds > 0 else { throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds) }
```

**What correct looks like.** The CLI rejects a non-positive timeout at parse time with the same message the C99
tool uses.

**Smallest correct fix.** Add `guard value > 0` to both `--timeout-ms` branches (space-separated and `=` form)
in `NetworkServerOptions.parse`, throwing `invalidTransport("--timeout-ms requires a positive integer")`.

---

### F-repo-ops-16 — S3 / test — the nested Swift manifest is built but its tests are never run, and its two smoke executables are never executed

`file:line`: `.github/workflows/swift-ci.yml:41-44`, `Swift/Package.swift:132-171,172-236`

**What is wrong.** CI builds both package entry points ("Build both package entry points with safety
diagnostics"), but every test invocation targets the root manifest only (`swift test`, `swift test
--sanitize=address`, `swift test --sanitize=thread`). `swift test --package-path Swift` is never run, so the
nested manifest's own test-target declarations are only checked indirectly by
`Swift/check-manifest-sync.sh`. The same manifest declares `LibrarySmokeServer`/`LibrarySmokeClient`
executables (`Swift/Package.swift:132-171`); they are compiled by the `swift build --package-path Swift` step
and never run by any workflow, script or test — a grep for the executable names finds only the manifest and
their own sources.

**Evidence.**

```
$ grep -nE 'swift (build|test)' .github/workflows/swift-ci.yml
37:          swift build \
41:          swift build --package-path Swift \
74:          swift test
100:          swift test --sanitize=address
118:          swift test --sanitize=thread
$ git grep -n 'LibrarySmokeServer\|LibrarySmokeClient' -- . ':!build' ':!C99/out' ':!AUDIT' | grep -v Sources/LibrarySmoke
Swift/Package.swift:51:        .executable(
Swift/Package.swift:52:            name: "LibrarySmokeServer",
(no script, test or workflow runs them)
```

**What correct looks like.** If the nested manifest has its own entry point and smoke tools, CI either runs
`swift test --package-path Swift` (or documents why it is redundant) and executes the smoke binaries, or the
two executables are removed.

**Smallest correct fix.** Add `swift test --package-path Swift` as one step (it is a second build of the same
sources, so make it a separate matrix leg to avoid doubling the job), and either add a one-line smoke run
(`swift run --package-path Swift LibrarySmokeServer --quick`) or delete the two executables.

---

### F-repo-ops-17 — S3 / dead — `check_spikes_absent` in the release script cannot fail: neither manifest declares the spike targets

`file:line`: `Swift/build-release-apple-silicon.sh:16-24`, called at `:89-90` and `:111`

**What is wrong.** The release script greps the release output directory for `AppleQUICSpike` and
`NativeQUICCoreSpike` and exits 1 if either is present. The script's only build command is
`swift build -c release --arch arm64 --product <WebTransportClient|WebTransportServer>`; SwiftPM builds only
targets a manifest declares, and neither `Package.swift` nor `Swift/Package.swift` declares either spike
(the sources live under `Swift/Experiments/`, which has no `Package.swift`). So no code path can put those
names in the release directory and the guard is an always-true validator. The same invariant is separately
asserted where it can actually fail — the `release-products` conformance scenario reads the manifests and
requires the spike products to be absent (`WebTransportCLIConformance.swift:736-753`) — which makes the guard
redundant rather than load-bearing.

**Evidence.**

```
$ git grep -n 'AppleQUICSpike' -- Swift/Package.swift Package.swift
(none; no target or product declares it)
$ find Swift/Experiments -name 'Package.swift'
(none)
$ sed -n '62,67p' Swift/build-release-apple-silicon.sh
  for product in $products; do
    swift build \
      -c release \
      --arch arm64 \
      --product "$product"
```

**What correct looks like.** Either the check is deleted (the manifest-level conformance scenario is the real
guard), or it is made able to fail by scanning the *build plan* (`swift package describe --type json`) for
spike targets rather than the output directory it cannot reach.

**Smallest correct fix.** Delete `check_spikes_absent` and its three call sites, and leave a comment pointing
at the `release-products` scenario that owns the invariant.

---

### F-repo-ops-18 — S3 / deps — no third-party licence notice for OpenSSL, the C99 build's REQUIRED dependency

`file:line`: `LICENSE:1`, `C99/CMakeLists.txt:38` (`find_package(OpenSSL 3.0 REQUIRED)`)

**What is wrong.** The repository is MIT (`LICENSE`) and ships a shared library
(`libwebtransport.0.1.0.dylib`, and install/package targets) that links OpenSSL 3.x — Apache-2.0 licensed,
whose notice must be retained when binaries are redistributed. There is no `NOTICE`, `THIRD_PARTY` or
attribution file anywhere in the tree (`git ls-files | grep -iE 'notice|third.?party|license'` finds only
`LICENSE`, `C99/third_party/.gitkeep` and two shell scripts whose names contain "third-party"). `C99/third_party/`
is empty, so nothing vendored is covered either.

**Evidence.**

```
$ git ls-files | grep -iE 'notice|third.?party|license|copying'
C99/scripts/run-vps-third-party-interop.sh
C99/third_party/.gitkeep
LICENSE
Swift/run-third-party-interop.sh
Swift/run-vps-third-party-interop.sh
$ git grep -ni 'openssl' -- C99/README.md README.md LICENSE C99/docs | grep -i 'licen\|apache\|attribut'
(no output)
$ grep -n 'find_package(OpenSSL' C99/CMakeLists.txt
38:find_package(OpenSSL 3.0 REQUIRED)
```

**What correct looks like.** A short `THIRD_PARTY.md` (or a section in `C99/README.md`) naming OpenSSL, its
version floor and its Apache-2.0 licence, referenced from the packaging/install rules.

**Smallest correct fix.** Add `THIRD_PARTY.md` with the OpenSSL notice and link it from `C99/README.md` and
the install rules.

---

## Scanner runs (counts only; no secret value is reproduced)

| Tool | Scope | Result |
| --- | --- | --- |
| gitleaks 8.30.1 (`gitleaks git -v --no-banner .`) | full history, 503 commits, ~7.04 MB | **9 findings**: 3 × `private-key`, 6 × `generic-api-key` |
| trufflehog 3.97.4 (`trufflehog git file://… --only-verified`) | full history, 6254 chunks, ~11.77 MB | **0 verified, 0 unverified** |
| trivy 0.74.0 (`trivy fs --scanners vuln,secret,misconfig .`) | working tree | **0 vulnerabilities, 0 secrets**, **12 misconfigurations** (6 × DS-0002 HIGH, 6 × DS-0026 LOW) |

The 3 gitleaks `private-key` hits are `C99/tests/vectors/trust/ca-key.pem:1`,
`C99/tests/vectors/trust/leaf-key.pem:1` and `C99/tests/vectors/trust/other-ca-key.pem:1`. They are documented
test-only fixtures (`C99/tests/vectors/trust/README.md`: "These keys and certificates are for tests and for
nothing else… using one outside this test directory would be a mistake"), regenerated by `make-fixtures.sh`.
They are not live credentials and nothing trusts them; they still need an allowlist before a scanner is added
to CI (F-repo-ops-06). The 6 `generic-api-key` hits are false positives on Swift identifiers in
`Swift/Tests/WebTransportNetworkRuntimeTests/WebTransportServerIdentityTests.swift` (lines 134, 150, 189, 251,
399, 449 — the reported "secrets" are enumeration cases such as `.ellipticCurveP256` and the labels
`privateKeyDER:`/`certificateChain`). **No file:line in the repository contains a live-looking credential.**

---

## §5 placeholder sweep — what was checked and what was found

Markers and patterns searched across every tracked file except `build/` and `C99/out/`:

| Pattern | Result |
| --- | --- |
| `TODO` / `FIXME` / `HACK` / `XXX` / `WIP` / `STUB` (word boundary, case-insensitive) | **0 occurrences anywhere** (including docs) |
| `placeholder` / `dummy` / `lorem` / `stand-in` / `for now` / `hardcoded` | 11 / 0 / 0 / 2 / 3 / 2 occurrences, all read in context: QUIC tag/`length` placeholders in the encoder, a certificate-fixture comment, a documentation phrase. None is a stub on a non-test path. |
| `fatalError` / `preconditionFailure` | 0 in `Swift/Sources` |
| `abort(` / `exit(` in libraries | 0 in `C99/src`, `C99/apps`; `exit()` only in the Swift CLI `main.swift` files (normal CLI termination) |
| `sleep` / `usleep` / `nanosleep` / `Task.sleep` in sources | 0 in `Swift/Sources`, `C99/src`, `C99/apps` |
| `#if 0`, `#ifdef NEVER/DISABLED` | 0 |
| Empty function bodies `{ }` | 1 — `C99/src/runtime/udp_platform.h:446` `wt_udp_platform_release`, the documented POSIX no-op of a two-platform lifetime hook |
| Disabled tests (`@Test(.disabled)`, `XCTSkip`) | 0 |
| Always-true test assertions (`WT_EXPECT_TRUE(label, 1)`, `#expect(true)`) | 0 |
| Trust bypasses (`insecure`, `trustAll`, `skipVerification`, `acceptAny`) | 0 outside the documented development bypass, which the trust layer restricts to loopback names (`C99/src/tls/trust.c:182`, `Swift/Sources/WebTransportNetworkRuntime/WebTransportServerIdentity.swift:163-170`) |
| Config defaults pointing at `localhost` / `example.com` | Public defaults are loopback development defaults and are refused on a non-loopback bind; `example.com` appears only in tests/scenarios, never as a production default |
| Permanently pinned feature flags | `WEBTRANSPORT_C99_CRYPTO` accepts only `openssl` and raises `FATAL_ERROR` otherwise (`C99/CMakeLists.txt:29-38`) — an explicit fail-closed choice, not a silent pin |

Findings that came out of this sweep: F-repo-ops-07 (default server prints a false readiness message) and
F-repo-ops-17 (always-true validator).

---

## §6 unused-code rule — reachability proofs performed

Per the rule, "unused" was never concluded from a grep alone. For each candidate the proof is stated, and the
legitimate reachability reasons (dynamic dispatch, registry, string lookup, serialization, exported public API,
scripts, CI, cross-project callers) were considered explicitly:

- **C99 public API (717 distinct `wt_*` names declared in `C99/include/**/*.h` vs 721 global symbols in the
  built `libwebtransport.a`)**: every declared function is defined and exported — 0 unresolved. (`wt_status_t`
  was a regex artifact: a typedef matched because it is followed by `(` in a function-pointer typedef.)
  Also checked per symbol: the library's own callers, `C99/apps`, `C99/tests`, `C99/scripts`, CMake and CI.
  Three names have no caller anywhere (F-repo-ops-08), kept as SUSPECTED because they are exported public API.
- **Orphan source files**: every `.c` under `C99/src` and `C99/apps` appears in a `CMakeLists.txt` source list;
  no orphan was found. Swift files are covered by directory-level `path:` declarations in both manifests.
- **`Swift/Experiments/AppleQUICSpike` and `NativeQUICCoreSpike`**: not declared in either manifest and not
  built by any script, but *not* reported as dead — the release script names both spikes as products that must
  not ship (`Swift/build-release-apple-silicon.sh:11,16-24`) and the conformance suite asserts their absence
  from the manifests (`WebTransportCLIConformance.swift:736-753`). They are documented spikes, so the
  reachability reason is "referenced by the release/CI contract"; the guard itself is vacuous
  (F-repo-ops-17).
- **`Swift/Sources/LibrarySmokeServer` / `LibrarySmokeClient`**: declared in the nested manifest only, built by
  CI, executed nowhere in the tree → F-repo-ops-16 (SUSPECTED removal candidate).
- **`C99/scripts/run-container-interop-server.sh`**: 0 references anywhere, but it is a helper a human runs
  alongside `run-container-interop.sh` (which is documented in both READMEs), so it is not concluded dead.
- **`Swift/run-external-interop.sh`**: 0 references; the README documents the interop scripts by directory,
  so this is a manual operator tool. Not concluded dead.

---

## Categories checked, and which are CLEAN

| Category | Status in this area |
| --- | --- |
| `placeholder` | 1 finding (F-repo-ops-07); otherwise clean — 0 TODO/FIXME/HACK/XXX/WIP/STUB markers, 0 `fatalError`, 0 library `abort`/`exit`, 0 `sleep`-as-work, 0 disabled or empty tests, 0 canned/mocked data outside tests, 0 trust bypasses outside the documented loopback one |
| `dead` | 2 findings (F-repo-ops-08 SUSPECTED, F-repo-ops-17) from the §6 sweep; no orphan source file found |
| `deps` | F-repo-ops-02, -12, -14, -18 (build output, action pinning, generated badge file, licence notice) |
| `test` | F-repo-ops-01, -06, -13, -16 (toolchain coverage, secret scanning, container hardening, nested-manifest tests) |
| `docs` | F-repo-ops-03, -04, -05, -09, -10, -11 (README/workflow/security-policy accuracy) |
| `incomplete` | F-repo-ops-15 (startup config validation) |
| `style` | CLEAN in this area. The formatting gate is real and blocking (`swift format lint --strict`), `.swift-format` is present, and no naming/format defect was found beyond the comment-staleness items already reported under `docs`. |
| `perf` | CLEAN for the repository/ops scope. No build-time, CI-time or startup-path performance defect was found; the C99 suite runs in 19 s and the Swift suite in ~15 s. Runtime performance is another examiner's area. |
| `logic`, `unsafe`, `bug` | Not audited here by design — they are the line-level Swift/C99 examiners' areas. Nothing in the repository/ops checks produced a finding in these categories, so this area contributes **no** logic/unsafe/bug findings rather than declaring them clean repo-wide. |
