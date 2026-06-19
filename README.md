# WebTransport

Native HTTP/3 WebTransport implementation work. Swift is the active
implementation; C99 and C++ are currently planned language ports.

Project documentation lives in the GitHub wiki:

- [WebTransport Wiki](https://github.com/Pummelchen/WebTransport/wiki)
- [Protocol Bible](https://github.com/Pummelchen/WebTransport/wiki/Protocol-Bible)
- [Swift macOS 26 Plan](https://github.com/Pummelchen/WebTransport/wiki/Swift-macOS26-Plan)

Repository layout:

```text
Swift/   Active Swift implementation
C99/     Planned C99 implementation
CPP/     Planned C++ implementation
```

Swift status highlights:

- `Swift/PRODUCTION_READINESS_AUDIT.md` records the 2026-06-19 production-readiness audit and the follow-up closure pass for the go-live blockers found there.
- `WebTransport` is the public Swift package product. It exposes an async
  client/server facade over the native HTTP/3 WebTransport core, with
  app-style `WebTransportClient` and `WebTransportServer` CLI products for
  deterministic loopback validation.
- `WebTransportClient --scenario all` and `WebTransportServer --scenario all`
  run the shared CLI conformance harness across session setup, settings, QPACK,
  datagrams, streams, close/drain, flow control, error mapping, GOAWAY,
  prompt-free security negatives, multi-session behavior, and release-surface
  checks. Failures are logged under `.webtransport-cli-logs/`.
- `WebTransportTLSCore` includes TLS 1.3 transcript/key schedule helpers plus a `TLSQUICConnectionState` integration state for CRYPTO flights, handshake/application traffic secrets, key updates, application `CONNECTION_CLOSE`, and QUIC final-size close paths.
- `WebTransportHTTP3Core` includes deterministic WebTransport ALPN/settings/session-policy rejection paths, a `LibrarySmokeClient`/`LibrarySmokeServer` matrix, and an executable draft-15 compliance definition-of-done matrix.
- `NativeQUICCoreSpike` and `AppleQUICSpike` remain internal spike targets, but
  they are no longer production package products and are rejected from release
  packaging if stale binaries are present.
