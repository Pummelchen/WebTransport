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
# Start Here

## Pasteable first-session prompt

```text
You are working in the WebTransport repository. Before editing anything, read AI_INDEX.md, AGENTS.md, .ai/PROJECT_MAP.md, .ai/ARCHITECTURE.md, .ai/COMMANDS.md, .ai/TESTING.md, and .ai/SECURITY.md.

Treat these onboarding files as guidance, not as a substitute for current source code. Inspect the current files relevant to my task before making changes. Separate verified facts, assumptions, inferences, unknowns, and conflicts. If docs and source disagree, trust current source, package manifests, CI, and tests before generated docs.

After inspecting the relevant files, summarize your understanding, identify the likely edit set, call out risks, and propose a validation plan. Keep changes narrow. Do not edit generated build outputs. Do not create model- or vendor-specific instruction files. Keep logs and docs free of private access data, TLS material, packet bytes, raw session IDs, datagram payloads, and close reason text.

When finished, report changed files, validations actually run, validations skipped, and remaining risks.
```

## Reading order

1. `AI_INDEX.md`
2. `AGENTS.md`
3. `.ai/PROJECT_MAP.md`
4. `.ai/ARCHITECTURE.md`
5. `.ai/COMMANDS.md`
6. `.ai/TESTING.md`
7. `.ai/SECURITY.md`
8. `.ai/COMPONENTS.md`
9. `.ai/PLAYBOOKS.md`
10. `.ai/KNOWN_UNKNOWNS.md`

## Before editing

- Open relevant source files, tests, package manifests, and CI workflow sections.
- Check whether the task touches public API, CLI behavior, runtime trust, parser logic, release scripts, or planned C99/C++ work.
- Avoid generated outputs.
- Treat onboarding docs as a map, not as proof.

## Understanding summary format

```md
Facts:
- ...

Assumptions:
- ...

Inferences:
- ...

Unknowns / conflicts:
- ...

Plan:
1. ...

Validation:
- ...
```

## Completion report

Include changed files, what changed, checks actually run, skipped checks, and remaining risks.
