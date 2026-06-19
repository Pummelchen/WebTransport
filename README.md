# WebTransport

Native HTTP/3 WebTransport implementations for Swift, C99, and C++.

Project documentation lives in the GitHub wiki:

- [WebTransport Wiki](https://github.com/Pummelchen/WebTransport/wiki)
- [Protocol Bible](https://github.com/Pummelchen/WebTransport/wiki/Protocol-Bible)
- [Swift macOS 26 Plan](https://github.com/Pummelchen/WebTransport/wiki/Swift-macOS26-Plan)

Repository layout:

```text
Swift/   Swift implementation
C99/     C99 implementation
CPP/     C++ implementation
```

Swift status highlights:

- `WebTransportTLSCore` includes TLS 1.3 transcript/key schedule helpers plus a `TLSQUICConnectionState` integration state for CRYPTO flights, handshake/application traffic secrets, key updates, application `CONNECTION_CLOSE`, and QUIC final-size close paths.
- `WebTransportHTTP3Core` includes deterministic WebTransport ALPN/settings/session-policy rejection paths for prompt-free negative security tests.
- `NativeQUICCoreSpike` exercises UDP frame exchange, QUIC packet protection, TLS/QUIC handshake state, HTTP/3 control/request handling, and WebTransport session establishment without interactive security prompts.
