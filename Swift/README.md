# Swift Implementation

This directory will contain the native Swift implementation of HTTP/3 WebTransport.

Current Phase 1 status: closed.

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
  and is tested against RFC 9001 sample vectors.
- `WebTransportCryptoApple` also proves Handshake/1-RTT style packet protection
  mechanics with AEAD seal/open, tamper rejection, nonce construction, and AES
  header-protection mask generation.
- `WebTransportUDPApple` provides prompt-free loopback UDP I/O for native packet
  tests.
- `NativeQUICCoreSpike` proves native STREAM, DATAGRAM, RESET_STREAM,
  STOP_SENDING, and CONNECTION_CLOSE frame exchange over Apple UDP without using
  Network.framework QUIC, then proves packet-protection seal/open and header-mask
  generation.
- `WebTransportTLSCore` now contains TLS 1.3 transcript hashing, HKDF label/key
  schedule helpers, Finished verify-data generation, ALPN `h3` extension encoding,
  QUIC transport-parameter extension encoding, typed ClientHello/ServerHello/
  EncryptedExtensions/Certificate/CertificateVerify/Finished bodies, TLS 1.3
  supported_versions, key_share, and signature_algorithms extension helpers,
  X25519 handshake secret derivation, application traffic secret progression,
  prompt-free identity/trust input models, and CertificateVerify verification
  primitives.
- `WebTransportTLSCore` also provides a CRYPTO-frame handshake flight encoder and
  decoder that fragments typed TLS messages into QUIC CRYPTO frames, reassembles
  out-of-order CRYPTO data, emits complete handshake messages, and updates the
  TLS transcript.
- `WebTransportHTTP3Core` contains HTTP/3 frame header codecs, SETTINGS payload
  encoding/decoding, unidirectional stream type parsing, and a versioned
  WebTransport-over-HTTP/3 draft-15 constants table.

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
