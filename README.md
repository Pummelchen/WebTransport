# WebTransport

WebTransport is a native implementation project for the HTTP/3 WebTransport protocol.
The repository is organized around three independent implementations:

- Swift
- C99
- C++ under the `CPP` directory, avoiding `+` characters in paths and tooling

Each implementation is intended to provide a reusable library plus client and server
test environments. The project goal is to build the required protocol layers without
external libraries.

## Project Bible

The authoritative protocol reference for this project is the latest IETF
`draft-ietf-webtrans-http3` document:

- Canonical datatracker page: <https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>
- Current draft snapshot checked on 2026-06-19: `draft-ietf-webtrans-http3-15`
- Intended RFC status: Proposed Standard

Until the document is published as a final RFC, implementation decisions must follow
the latest draft available from the canonical datatracker page. Do not treat an older
draft revision, browser behavior, blog post, sample implementation, or local design
note as more authoritative than the current IETF draft.

See [docs/Protocol-Bible.md](docs/Protocol-Bible.md) for the project rules around
using this reference.

## Project Goals

- Implement HTTP/3 WebTransport natively in Swift, C99, and C++.
- Provide a reusable library API for each language implementation.
- Provide local client and server test programs for each implementation.
- Keep implementations self-contained, with no third-party protocol, TLS, QUIC, or
  HTTP/3 libraries.
- Keep the three implementations comparable in behavior, test coverage, and protocol
  validation.

## Repository Layout

```text
WebTransport/
  Swift/   Native Swift implementation, library, and test clients/servers
  C99/     Native C99 implementation, library, and test clients/servers
  CPP/     Native C++ implementation, library, and test clients/servers
```

## Implementation Scope

The planned scope includes:

- QUIC transport primitives required by HTTP/3 WebTransport.
- TLS handshake integration required for QUIC.
- HTTP/3 frame parsing and serialization.
- WebTransport session setup over HTTP/3.
- Bidirectional and unidirectional stream handling.
- Datagram support where required by the WebTransport protocol.
- Client and server test environments for interoperability checks.
- Shared protocol test vectors where practical.

## Constraints

- No external libraries.
- No generated protocol implementation from third-party projects.
- Prefer clear, auditable protocol code over opaque abstraction.
- Keep platform-specific code isolated behind small internal interfaces.

## Status

Initial repository structure and documentation are in place. Protocol implementation
work has not started yet.

## Development Notes

Each language directory will maintain its own build instructions once code is added.
The top-level README and project wiki should stay aligned as architecture, milestones,
and test strategy evolve.
