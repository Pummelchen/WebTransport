# WebTransport

Native Swift WebTransport over HTTP/3 client and server APIs.

The implementation targets IETF `draft-ietf-webtrans-http3-16` (6 July 2026).

## Overview

The `WebTransport` module exposes the public Swift concurrency API for
opening WebTransport sessions, bidirectional streams, datagrams, and graceful
close/drain flows.

Use ``WebTransportClient`` to establish outbound sessions and
``WebTransportServer`` to accept inbound sessions. The production package routes
network I/O through the WebTransport Network.framework runtime, while the
deterministic protocol cores (`WebTransportQUICCore`, `WebTransportTLSCore`,
`WebTransportHTTP3Core`, `WebTransportUDPApple` and `WebTransportCryptoApple`)
are published as library products so embedders and conformance tooling can drive
the protocol directly. Send-only and receive-only WebTransport streams are
implemented in the `WebTransportHTTP3Core` session manager; the `WebTransport`
session API exposes bidirectional streams, datagrams, and — through
``WebTransportSession/acceptUnidirectionalStream(maximumInitialBytes:)`` — a
**receive-only** ``WebTransportUnidirectionalStream`` for a stream the peer
initiated. A peer-initiated unidirectional stream is receive-only because RFC
9000 section 2.1 gives a unidirectional stream to its initiator, so the accepted
type deliberately has no `send`; the peer must have been granted
`initialMaxUnidirectionalStreams`, and a stream beyond the runtime's
per-direction inbound ceiling is refused with `WT_BUFFERED_STREAM_REJECTED`.
Opening a locally initiated unidirectional stream is not exposed by the
`WebTransport` session API.

Client configurations can provide optimistic CONNECT capsules through
``WebTransportClientConfiguration/optimisticCapsules``. The runtime sends them
with CONNECT, and servers process them only after accepting the session.
Established sessions expose draft-16 session-bound TLS exporter material through
``WebTransportSession/exportKeyingMaterial(applicationLabel:applicationContext:outputByteCount:)``.

## Topics

### Client

- ``WebTransportClient``
- ``WebTransportClientConfiguration``
- ``WebTransportEndpoint``

### Server

- ``WebTransportServer``
- ``WebTransportServerConfiguration``

### Sessions

- ``WebTransportSession``

### Streams

- ``WebTransportBidirectionalStream``
- ``WebTransportUnidirectionalStream``

### Logging and Errors

- ``WebTransportLogger``
- ``WebTransportLogEvent``
- ``WebTransportErrorSurface``
