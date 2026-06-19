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

- `Swift/PRODUCTION_READINESS_AUDIT.md` records the 2026-06-19 production-readiness audit, fixes landed from that audit, and the remaining go-live blockers.
- `WebTransportTLSCore` includes TLS 1.3 transcript/key schedule helpers plus a `TLSQUICConnectionState` integration state for CRYPTO flights, handshake/application traffic secrets, key updates, application `CONNECTION_CLOSE`, and QUIC final-size close paths.
- `WebTransportHTTP3Core` includes deterministic WebTransport ALPN/settings/session-policy rejection paths, a `LibrarySmokeClient`/`LibrarySmokeServer` matrix, and an executable draft-15 compliance definition-of-done matrix.
- `NativeQUICCoreSpike` exercises UDP frame exchange, QUIC packet protection, TLS/QUIC handshake state, HTTP/3 control/request handling, WebTransport session establishment, the library smoke matrix, and the compliance matrix without interactive security prompts.
