# Swift Implementation

This directory will contain the native Swift implementation of HTTP/3 WebTransport.

Current Phase 1 status:

- `AppleQUICSpike` proves prompt-free localhost QUIC listener/client startup,
  HTTP/3 ALPN negotiation, client-initiated bidirectional streams,
  client-initiated unidirectional streams, and server inbound stream acceptance
  using only Apple SDK frameworks.
- The runtime identity is generated in memory from a non-persistent `SecKey` and a
  generated self-signed certificate. It does not create, import, search, or modify
  keychains.
- QUIC datagrams are currently blocked: `NetworkConnection<QUIC>` negotiates
  `usableDatagramFrameSize == 0` on both peers even when both sides configure
  `.maxDatagramFrameSize(1_200)`.
- Full close/reset/application-error behavior is not yet proven. The relevant
  properties are exposed by Network.framework, but runtime mutation was not safe
  enough to claim as complete in the spike.
- `WebTransportQUICCore` now contains native QUIC byte, varint, packet-number,
  transport-parameter, long-header packet, and frame codecs.
- `WebTransportCryptoApple` derives QUIC v1 Initial secrets with Apple CryptoKit
  and is tested against the RFC 9001 sample vector.
- `WebTransportUDPApple` provides prompt-free loopback UDP I/O for native packet
  tests.
- `NativeQUICCoreSpike` proves native STREAM, DATAGRAM, RESET_STREAM,
  STOP_SENDING, and CONNECTION_CLOSE frame exchange over Apple UDP without using
  Network.framework QUIC.

Commands:

```sh
swift build
swift test
swift run AppleQUICSpike --loopback
swift run NativeQUICCoreSpike
./build-release-apple-silicon.sh
```

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
