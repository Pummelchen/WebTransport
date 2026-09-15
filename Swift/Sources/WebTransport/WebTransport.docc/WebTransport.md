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
session API currently exposes bidirectional streams and datagrams.

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

### Logging and Errors

- ``WebTransportLogger``
- ``WebTransportLogEvent``
- ``WebTransportErrorSurface``
