<!--
AI onboarding file.
Mode: bootstrap
Indexed commit: 742358be03922065f4aca3af823d36df5993204d
Last generated: 2026-06-26T15:16:55+02:00
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# Security Notes for AI Agents

This repository implements network protocols, TLS/QUIC behavior, HTTP/3 parsing, QPACK parsing, WebTransport sessions, streams, datagrams, and CLI/runtime surfaces. Treat peer input and CLI/environment input as adversarial.

Evidence:
- `SECURITY.md`
- `Swift/Sources/WebTransport/WebTransport.swift`
- `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift`
- `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift`
- `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift`
- Public API and process tests.

## Admission policy

No application-level user auth system was detected. Relevant access checks are protocol/session checks: CONNECT authority, path, optional origin, subprotocol selection, and HTTP/3 WebTransport settings validation.

Primary source: `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift`.

## Trust and certificates

Verified behavior:

- `systemTrust` is default.
- `localDevelopmentSelfSigned` is test/local-development oriented.
- Local self-signed trust is rejected for non-loopback hosts before connection.
- Accepted loopback hosts are `localhost`, `127.0.0.1`, and `::1`.
- CLI clients require explicit `--trust local-self-signed` for local self-signed loopback use.

Do not broaden local self-signed trust without human review.

## Sensitive material rules

Do not add, log, or commit private access data, private keys, production certificates, TLS material, QUIC packet-protection material, packet captures containing private material, peer payloads, raw session IDs, or close reason text.

The public API includes sanitized logging and public error descriptions. Preserve that behavior.

## Sensitive paths

| Path | Concern |
|---|---|
| `Swift/Sources/WebTransportNetworkRuntime/` | Trust policy, endpoint/session handling, Network.framework runtime. |
| `Swift/Sources/WebTransportTLSCore/` | TLS verification and key schedule. |
| `Swift/Sources/WebTransportCryptoApple/` | QUIC crypto helpers. |
| `Swift/Sources/WebTransportHTTP3Core/` | Peer-controlled parsing, buffering, session policy, flow control. |
| `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift` | Low-level UDP helper; loopback invariant. |
| `Swift/Sources/WebTransportClient/main.swift` | CLI endpoint/trust behavior. |
| `Swift/Sources/WebTransportServer/main.swift` | CLI listen/session policy behavior. |
| `Swift/*.sh` | External interop and release behavior. |

## Agent rules

- Treat parser changes as security-sensitive.
- Keep buffer and stream/datagram limits explicit.
- Preserve deterministic malformed-input failure.
- Preserve public error redaction and sanitized logging.
- Do not add interactive certificate/trust prompts.
- Do not make test-only trust modes implicit for real endpoints.
- Follow `SECURITY.md` for vulnerability reporting.
