# Third-party notices

This repository is distributed under the MIT licence (see `LICENSE`). The C99
library and its command-line tools depend on the third-party component below,
whose licence notice is retained here for redistribution. The Swift package does
not link it: its TLS and crypto live in `Swift/Sources/WebTransportTLSCore` and
`Swift/Sources/WebTransportCryptoCore` and use the platform frameworks.

## OpenSSL

- **Version:** 3.0 or later. `C99/CMakeLists.txt` declares
  `find_package(OpenSSL 3.0 REQUIRED)`, so a C99 build cannot be configured
  without it.
- **Licence:** Apache License 2.0. The full text is distributed with OpenSSL
  (`LICENSE.txt` in an OpenSSL source tree) and at
  <https://www.apache.org/licenses/LICENSE-2.0>; a redistributor must carry it
  from there.
- **Used by:** `libwebtransport` (static and shared) and the `wt-client-c99`,
  `wt-server-c99` and `wt-conformance-c99` tools, which link `OpenSSL::Crypto`
  for the TLS 1.3 handshake, the record layer and the cryptographic primitives.
  The link is `PRIVATE` (`C99/CMakeLists.txt`), so no OpenSSL type appears in a
  public header, but a binary that embeds the library is still a redistribution
  of OpenSSL.
- **Satisfying the notice:** carry this file, or OpenSSL's own `LICENSE.txt`,
  with any binary distribution that includes `libwebtransport` or the C99 tools.
  The install rules put this file in the install tree under
  `<prefix>/share/doc/webtransport_c99/` for exactly that reason, and
  `C99/scripts/check-package.sh` asserts it is there.
