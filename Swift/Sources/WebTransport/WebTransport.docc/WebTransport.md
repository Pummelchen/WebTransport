# WebTransport

Native Swift WebTransport over HTTP/3 client and server APIs.

## Overview

The `WebTransport` module exposes the public Swift concurrency API for
opening WebTransport sessions, bidirectional streams, unidirectional streams,
datagrams, and graceful close/drain flows.

Use ``WebTransportClient`` to establish outbound sessions and
``WebTransportServer`` to accept inbound sessions. The production package routes
network I/O through the WebTransport Network.framework runtime and keeps
deterministic protocol helpers out of the public release surface.

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
