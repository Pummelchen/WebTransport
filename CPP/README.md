# C++ Implementation

This directory will contain the native C++ implementation of HTTP/3 WebTransport.

The directory is named `CPP` to avoid `+` characters in paths and tooling.

Planned contents:

- Reusable C++ library.
- Client test environment.
- Server test environment.
- C++-specific protocol tests.

Constraints:

- No external libraries.
- Keep protocol behavior aligned with the Swift and C99 implementations.
- Keep platform-specific networking and cryptographic primitives isolated behind
  internal interfaces.
