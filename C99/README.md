# C99 Implementation

This directory will contain the native C99 implementation of HTTP/3 WebTransport.

Planned contents:

- Reusable C99 library.
- Client test environment.
- Server test environment.
- C99-specific protocol tests.

Constraints:

- No external libraries.
- Use C99-compatible language features.
- Keep protocol behavior aligned with the Swift and C++ implementations.
- Keep platform-specific networking and cryptographic primitives isolated behind
  internal interfaces.
