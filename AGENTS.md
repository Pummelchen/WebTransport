<!--
AI onboarding file.
Mode: bootstrap
Indexed commit: 742358be03922065f4aca3af823d36df5993204d
Last generated: 2026-06-26T15:16:55+02:00
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# Generic Agent Instructions

These instructions apply to any high-capability AI coding agent working in this repository.

## Start every session

1. Read `AI_INDEX.md`, then `.ai/START_HERE.md`, `.ai/PROJECT_MAP.md`, and `.ai/COMMANDS.md`.
2. Inspect current source files before planning edits.
3. Separate verified facts, assumptions, inferences, unknowns, and conflicts.
4. Trust current source, package manifests, CI, and tests before generated docs.
5. Keep changes narrow and report validation actually run.

## Source-of-truth order

1. Current source code.
2. Build/test/deployment configuration.
3. CI workflows.
4. Package metadata.
5. Tests.
6. Current README/docs.
7. Older comments or historical notes.
8. Inference.

## Project-specific rules

- Swift is the active implementation.
- Root `Package.swift` is the public package; `Swift/Package.swift` also contains smoke executables and test support.
- C99 and C++ folders are planned skeletons unless current files prove otherwise.
- Real `--listen` and `--connect` CLI sessions require `--transport packet`.
- Local self-signed trust is explicit and loopback-limited to `localhost`, `127.0.0.1`, and `::1`.
- Keep public logs and errors sanitized. Do not expose private access data, TLS material, certificate material, packet bytes, datagram payloads, raw session IDs, or close reason text.
- Avoid generated outputs under `.build/`, `Swift/.build/`, `.webtransport-cli-logs/`, `C99/out/`, and `CPP/out/`.

## Planning checklist

- Identify source files, tests, docs, and commands affected by the task.
- State what is verified from files and what is inferred.
- Note security-sensitive areas before changing protocol, networking, trust, parser, crypto, or CLI input paths.
- Do not open a pull request unless the user explicitly asks.

## Validation expectations

| Change area | Expected checks |
|---|---|
| Docs/onboarding | Link check, manifest JSON parse, generated-file review. |
| Public Swift API | `swift build`, `swift test`, `cd Swift && ./check-api-compatibility.sh`. |
| CLI behavior | `swift test`, `swift run WebTransportClient --scenario all`, `swift run WebTransportServer --scenario all`. |
| Runtime/trust/networking | Public API tests, process tests, loopback packet client/server checks. |
| Release scripts/artifacts | `cd Swift && ./build-release-apple-silicon.sh` and CI review. |
| C99/C++ plans | Validate claims against current Swift source and plan READMEs. |

Never claim a check passed unless it was run in the current session.

## Commit expectations

- Commit only requested, relevant files.
- Never push directly to `main`.
- Scan changed files for private access data or accidental sensitive material before committing.
- Keep generated AI onboarding files vendor-neutral.
- Do not create model- or vendor-specific instruction files.

## Refresh policy

Refresh these files after meaningful changes to:

- `README.md`, `Swift/README.md`, `Package.swift`, `Swift/Package.swift`
- `.github/workflows/**`
- `Swift/Sources/**`
- `Swift/Tests/**`
- `Swift/*.sh`
- `C99/**`, `CPP/**`, or security/release docs
