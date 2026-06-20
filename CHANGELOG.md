# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning.

## Unreleased

- Hardened Swift runtime endpoint reporting, local self-signed trust handling, and `@unchecked Sendable` documentation.
- Restricted the Swift UDP packet-probe helper to explicit loopback use and added IPv6 loopback coverage.

## [1.0.0] - 2026-06-20

- Swift implementation exposed as a repository-root SwiftPM package.
- Swift WebTransport compatibility documented as 100% against `draft-ietf-webtrans-http3-15`.
- Swift interop validated against `pywebtransport`/`aioquic`, `web-transport-quinn`, and `web-transport-quiche`.
- Added a Debian 13 VPS interop runner covering five third-party implementations: `pywebtransport`/`aioquic`, `web-transport-quinn`, `web-transport-quiche`, `hyperium/h3-webtransport`, and `erlang-webtransport`.
- MIT license added.
- Security reporting policy added.
- DocC catalog added for the public Swift API.
