# Release and build rules — WebTransport

The release and build standard for this repository.

**This file belongs to this repository.** Edit it here and nowhere else. It was once
deployed from a master document kept in another repository; that arrangement is gone.
Nothing outside this repository governs these rules or can overwrite this file, and an
agent working here never needs to leave the repository to find the standard.

**Part 1 is the rule set** and **Part 2 is this repository's own section**; where the
two appear to disagree, Part 2 wins.

---

# Part 1 — Generic rules

## 1.1 Scope

These apply to any repository that produces a **runnable artifact**: a binary, a
library, an image, a package. Repositories that only hold documents, data or
configuration are out of scope, and should say so in their Part 2 section rather
than adopting a release process they cannot use.

## 1.2 Non-negotiable

1. **Apple Silicon only.** Build native `arm64`. This covers M1–M6. Never
   `--arch x86_64`, never `ARCHS=arm64 x86_64`, and never `lipo -create` — that
   is how a universal binary gets made, and there is no x86_64 build.
2. **Assert it, do not assume it.** After building, check the artifact:
   `lipo -archs <binary>` must be exactly `arm64`. A build that silently produced
   a fat binary is a release defect, not a build option.
3. **Every release carries the artifacts.** A tag alone is not a release. If the
   Release page has no binaries attached, the release did not happen.
4. **No hardcoded build-toolchain triple in a path.** `.build/release` is the
   stable spelling. `.build/arm64-apple-macosx/release` points at nothing on a
   newer toolchain and at a stale binary on this one. The one exception is a build
   that explicitly passes `--arch arm64`: then the triple directory really is
   where SwiftPM writes, and that build must also assert the arch (§1.2.2).
5. **One checksummed artifact per target, or one checksum file covering all of
   them.** Never publish a binary without a digest beside it.
6. **Dry run by default; publish only on an explicit flag.**
7. **Never fetch a model, dataset or dependency to make a gate pass.** A check
   that cannot run is reported *not checked* — and the release notes must name it.
   "Not checked, no input" and "checked and identical" are different sentences.

## 1.3 Identity

The version or build number is **single-sourced and enforced**, not maintained by
hope.

- **One authoritative value.** A file at the repository root — `VERSION` for a
  semantic version, `BUILD_NUMBER` for a build number. Anywhere else it appears
  is a **mirror**, and the build or CI must fail when a mirror disagrees.
- **Pick one scheme and state it.** Semantic versions (`vX.Y` or `vX.Y.Z`) or build
  numbers (`b1`, `b2`). Whichever you pick, a release must not *introduce* a further
  component: if the scheme is `X.Y`, a bug-fix release is `X.(Y+1)` and not `X.Y.1`.
  Do not mix them, and do not "helpfully" introduce versions into a
  project that uses build numbers.
- **The build refuses a malformed or inconsistent identity.** Fail at configure
  or compile time, not at release time.
- **Identity is observable.** A user must be able to say what they are running
  from the artifact alone: the archive filename, or the program's own answer, or
  both.
- **Bump once, propagate mechanically.** Provide a command that writes the mirrors
  from the authoritative value. A release is one edit plus one command.
- **A second declaration in a test is a defect.** Derive the expected value from
  the source of truth; a literal in a test means every bump fails a test that is
  not about the version, and the tempting fix — editing the test — is how a wrong
  version ships.
- **Multi-library projects version in lockstep.** Libraries that ship together and
  interoperate carry the **same** version, because a caller pairing them has no
  other way to know the pair is compatible. A library with no code change is
  recompiled and republished at the new number rather than left behind.
  Lockstep applies to the **library version only** — an ABI version, protocol
  draft, or schema version is a separate axis and must not be dragged along.

## 1.4 Preconditions

Before starting, confirm and record: the OS floor and toolchain floor are met
(`sw_vers`, `swift --version`); there is disk for a clean scratch build plus the
staged archive; `memory_pressure -Q` is acceptable; **no competing build or model
process is running**; `gh auth status` is the repository owner's account; the tree
is clean; and `HEAD` **is** the tag.

**Never terminate a process you did not start.** If one is blocking, name it with
its parent and age, and stop.

## 1.5 Gates

Run these in order, and make each one **able to fail**:

1. **Lint** — the project's own lint gates.
2. **Full test suite**, serially, and it must report the count that passed.
3. **Parity or golden checks** — real inference, real rendering, real protocol
   frames; whatever "the output is unchanged" means for this project.
4. **A clean scratch build** with the log scanned for warnings.

Two traps, both of which have shipped broken gates in this organisation:

- **A gate that cannot fail is not a gate.** A guard that looks for a file the
  build never produces passes for every input. A warning scan over an *incremental*
  build compiles nothing and passes vacuously — always use a fresh scratch path.
  Before trusting a new gate, break its input and watch it fail.
- **Guard the plan, not the byproduct.** Ask the build system what it resolved
  (`swift package describe --type json`, `cmake --build ... -t help`) rather than
  checking for artifacts after the fact.

## 1.6 Packaging

The archive contains, at minimum:

- the **executables or libraries**, built for arm64;
- **resource bundles** — a Swift binary without its `.bundle` cannot load its
  Metal kernels, and this fails at runtime rather than at build time;
- `LICENSE`, and `NOTICE` / `THIRD_PARTY_NOTICES.md` where third-party code is
  redistributed;
- a **`README-binaries.txt`** stating the platform floor, that the build is
  Apple-Silicon-only, and that the binaries are **not code-signed or notarized** —
  with the quarantine command (`xattr -dr com.apple.quarantine <path>`) so a user
  who verified the checksum can run them. Do not imply a notarized build.

Name the archive `<project>[-<library>]-<version>-macos-arm64.tar.gz`; the
library segment is required only for a multi-library project, and exists so two
artifacts of the same release are distinguishable.

## 1.7 Publishing

```bash
gh release create "$TAG" "$ARCHIVE" "$ARCHIVE.sha256" \
  --repo <owner>/<repo> --title "<Project> $VERSION" \
  --notes-file "$NOTES" --latest
```

**Pin `--repo` on every `gh` call.** In a fork `gh` defaults to the *parent*
repository, so `gh release list` shows another project's releases and
`gh release create` fails with a misleading "tag has not been pushed".

## 1.8 Release notes

- Full notes in `docs/release-notes-vX.Y.Z.md` (or the repository's equivalent),
  one section per user-visible change, each naming the check that backs it.
- End with a checksum block carrying `SHA256_PENDING` and
  `ARCHIVE_BYTES_PENDING`, substituted at publish time. **Never copy a size out
  of a dry run** — publish rebuilds, and the archive differs.
- `--publish` must **refuse** unless the notes carry the placeholder or quote the
  real value. A release quoting the wrong digest is worse than one quoting none.
- Name **every** check that did not run, and why.
- The README gets **no release callout**. It changes only when a fact it states
  changes. The release notes are the announcement.
- **There is no separate changelog file: the release notes *are* the changelog.**
  Each release's notes — `docs/release-notes-vX.Y.Z.md` here, and the body published
  for the tag — are organised as `### Swift`, then `### C99`, then `### Both`, because
  the two libraries are independent and a reader of one should not have to filter the
  other's entries out. Each library's changes go under its own heading and nowhere
  else; a change that is genuinely one item — a wire fix made on both sides for the
  same RFC reason, the version lockstep, repository-wide tooling — is one entry under
  `### Both`, with both halves named, rather than two entries. The split starts with
  1.5.0; earlier releases keep the form they were published with.

## 1.9 After publishing

Verify the Release: the notes quote the digest in the `.sha256` beside it, the
assets are the archive and its checksum, and the release notes point at the same tag.
Leave previous releases' notes and performance tables alone.

## 1.10 Rules, agents and other repositories

- **These rules live in this repository and are edited only here.** They are not
  deployed from anywhere and nothing outside this repository can overwrite them. A
  rule an agent cannot find is a rule that will be broken, so a rule about this
  repository belongs in this file or in `AGENTS.md` — not in a shell-script comment,
  and not in another repository.
- **Work happens in this repository only.** Never commit, push, open a pull request
  against, or otherwise modify another repository. A change that appears to belong
  elsewhere is reported to the owner with the exact edit and the reason, not applied.
  Touching another repository requires an instruction that names it, and "the fix
  lives there" is not one.
- **`AGENTS.md` is the one instruction file, and every harness must reach it.** This
  account works with Codex, Claude Code, DeepSeek Harness, OpenCode, Qwen Code,
  Qoder and Zed. Six read `AGENTS.md` directly; **Claude Code does not** — its
  documentation is explicit that it reads `CLAUDE.md`, not `AGENTS.md` — so this
  repository also carries a committed `CLAUDE.md` whose entire content is the
  `@AGENTS.md` import. Commit it: a symlink made on one machine is invisible to a
  fresh clone, to CI and to every other checkout, and on Windows it needs
  Administrator rights. Qwen Code reads `AGENTS.md` alongside its own `QWEN.md`, so
  there is nothing to duplicate for it.
- **Never add a file that shadows `AGENTS.md`.** Zed takes the *first match* from
  `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
  `.github/copilot-instructions.md`, `AGENT.md`, and only then `AGENTS.md` — so any
  of those six silently replaces this file for every Zed user. Check for them whenever
  the instruction file changes.
- **An archived repository is read-only.** Nothing can be committed to it, so no
  release step may depend on one. Name the exclusion rather than leaving a gap.
- **A check that has never been seen to fail is not yet trusted.**

# Part 2 — This repository

## WebTransport — Swift **and** C99, semantic version, 12 releases

**One repository, two libraries, one version.** This is the project the lockstep
rule exists for.

- **Identity** semantic version. **The two libraries must always carry the same
  number** — if only one changed, recompile the other at the new number rather than
  leaving it behind.
- **The lockstep is landed and enforced** (it landed for the 1.4.0 release, in the
  commit that single-sourced the version, `f9a530b`): a root `VERSION`
  file is the single source, `WT_VERSION_*` in
  `C99/include/webtransport/version.h` and `library` in
  `Swift/Sources/WebTransport/WebTransportVersion.swift` are its mirrors, and
  `Swift/check-version-sync.sh` is the gate. A bump is one edit plus one command:
  write `VERSION`, then run `./Swift/check-version-sync.sh --write`. The C99 CMake
  configure fails on a mismatch as well, so a C99-only build cannot produce a
  library whose filename and whose `wt_version_string()` disagree.
- **A second declaration of the version in a test is a defect.** The C99 tests derive
  the expected string from the header's macros (`WT_TEST_VERSION_STRING`); a literal
  there would make every bump fail a test that is not about the version.
- **`WT_ABI_VERSION` is not part of the lockstep.** It moves only for a breaking
  layout or signature change; a bug-fix release moves the version and not the ABI.
  `wt_protocol_draft()` is a third, separate axis.
- **C99 artifacts** built by `C99/platform/macos26/compile-dylib.sh`;
  `C99/platform/{debian,freebsd}/compile-so.sh` for the other platforms. Each writes
  its own build directory (`out/<platform>/build-install`) and its own install tree
  (`out/<platform>/install`), deliberately NOT the `out/<platform>/build` that
  `C99/scripts/build-and-test.sh` configures with Ninja — the two use different
  generators and sharing a directory made whichever ran second fail.
  The install tree must be *usable*, not merely present: `check-package.sh` runs all
  three installed tools, because an installed tool that cannot find the installed
  library is not a product (the executables need the install rpath, which
  `C99/CMakeLists.txt` sets to `@loader_path/../lib`, `$ORIGIN/../lib` on ELF).
- **Swift artifacts** built by `Swift/build-release-apple-silicon.sh`, which is
  the most rigorous build in the organisation and the model for the rest:
  - `swift package describe --type json` is checked for experiment/spike targets
    **before** building, because a file-existence guard "could not fail for any
    input";
  - **two full build passes** with `SOURCE_DATE_EPOCH=0`,
    `SWIFT_DETERMINISTIC_HASHING=1`, `ZERO_AR_DATE=1`, compared by a **normalized
    Mach-O hash**, so the release is reproducible;
  - `lipo -archs` must report exactly `arm64`;
  - output lands in `.build/release-artifacts/` with a `SHA256SUMS`.
- **Gates** `Swift/check-toolchain.sh 6.4 27.0`, `Swift/check-manifest-sync.sh`
  (19 shared targets must agree across the two manifests), `Swift/check-version-sync.sh`,
  `Swift/check-target-imports.sh`, `Swift/check-pkcs12-keychain-free.sh` (a PKCS#12
  identity must resolve while the default keychain is **locked**, which is the only state
  in which the memory-only import is distinguishable from one that files the caller's key),
  `check-api-compatibility.sh`, the library smoke pair, the nested manifest's own test
  target, the client and server CLI conformance suites, and the C99
  `C99/scripts/check-*.sh` family — which since the pre-production audit also carries
  `check-format.sh` (every C source against the committed `.clang-format`),
  `measure-coverage.sh` (line coverage from an instrumented build, so it is measured
  rather than remembered) and `check-unused-locals.py` (a local assigned and never read,
  hidden from `-Wunused-but-set-variable` by a `(void)` cast). The Swift suite runs under
  ASan — the whole suite, not only the parser fuzz filter — and under TSan; the C99 suite
  runs under ASan+UBSan, with the sanitizer flags chosen per compiler because
  `-fno-sanitize=function` is clang-only and GNU C rejects it outright. The C99 CI also
  runs a `linux-debian13` job and two
  enforced Windows jobs (`windows-wine` under Wine, `windows-native` on
  `windows-latest`), and the CMake configure fails on a version-mirror mismatch.
  The `check-cli-*.sh` scripts run through CTest, not as workflow steps. `security-scan.yml`
  runs gitleaks over the full history and trivy over the tree, and `soak.yml` runs the
  connection-churn soak nightly rather than per pull request, because it watches resident
  memory and thread count for sustained growth and a loaded shared runner can move those
  numbers with nothing wrong.
- **Two manifests** — the root `Package.swift` and `Swift/Package.swift` —
  intentionally expose different product sets; shared targets must not diverge.
- **Publishing ships both libraries**, one artifact per library, under one tag and
  these notes — never a release named for or carrying only one of them. (1.4.0 is the
  first release that carries both; the 1.0–1.3 releases were Swift-only.) Today that is
  `./release-macos-arm64.sh`, which builds both, asserts `arm64` on every Mach-O it
  ships, packs `WebTransport-swift-<version>-macos-arm64.tar.gz` and
  `WebTransport-c99-<version>-macos-arm64.tar.gz` with a `.sha256` beside each, and
  is a dry run unless given `--publish` (or `--republish`, to correct a published
  Release in place, which also moves the tag when the correction changed the source).
  A release is the macOS arm64 pair: the `C99/platform/{debian,freebsd,windows11}`
  scripts build and check other platforms and are not release artifacts.
  The source of both libraries reaches users through the Release's own source
  archives for the tag. Each archive carries a `README-binaries.txt`; the C99 one
  names the OpenSSL 3 runtime dependency of the dylib, because that library is
  deliberately not bundled with it.
