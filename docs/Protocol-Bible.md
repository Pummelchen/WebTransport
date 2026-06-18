# Protocol Bible

The project bible for WebTransport protocol behavior is the latest IETF
`draft-ietf-webtrans-http3` document until it is replaced by a final RFC.

Canonical reference:

<https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>

As of 2026-06-19, the datatracker page identifies the current draft as
`draft-ietf-webtrans-http3-15`, an active Internet-Draft with intended RFC status
of Proposed Standard.

## Authority Rules

- Follow the latest revision listed on the canonical datatracker page.
- Treat the final RFC as authoritative once the draft is published as an RFC.
- Treat older draft versions as historical reference only.
- Treat browser behavior, sample code, blog posts, and local notes as secondary
  evidence only.
- If an implementation detail conflicts with the current draft, the draft wins
  unless the project explicitly documents a temporary compatibility exception.

## Update Rules

When a new draft revision appears:

1. Review normative changes and protocol wire-format changes.
2. Update implementation milestones and test vectors affected by the revision.
3. Update this file and the GitHub wiki with the new draft number and review date.
4. Record any intentional temporary divergence in the affected implementation folder.

## Implementation Rules

- Protocol constants, frame formats, stream rules, session setup, datagram behavior,
  flow control, error codes, and security requirements must trace back to the current
  draft or final RFC.
- Swift, C99, and C++ implementations should expose language-native APIs, but their
  wire behavior must remain aligned with the same protocol reference.
- Tests should name the draft revision they were written against when they validate
  draft-specific behavior.
