# Swift Implementation

This directory will contain the native Swift implementation of HTTP/3 WebTransport.

Planned contents:

- Reusable Swift library package.
- Client test environment.
- Server test environment.
- Swift-specific protocol tests.

Constraints:

- No external libraries.
- Keep protocol behavior aligned with the C99 and C++ implementations.
- Keep platform-specific networking and cryptographic primitives isolated behind
  internal interfaces.
