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
# Commands

Toolchain: Swift 6.3 on macOS 26, from `Package.swift` and CI.

- Build: `swift build`
- Test: `swift test`
- Focused public API tests: `swift test --filter WebTransportPublicAPITests`
- Focused process tests: `swift test --filter WebTransportProcessTests`
- Client conformance: `swift run WebTransportClient --scenario all`
- Server conformance: `swift run WebTransportServer --scenario all`
- Client help: `swift run WebTransportClient --help`
- Server scenario list: `swift run WebTransportServer --list`
- Local IPv4 server: `swift run WebTransportServer --listen 127.0.0.1:4433 --transport packet`
- Local IPv4 client: `swift run WebTransportClient --connect 127.0.0.1:4433 --transport packet --trust local-self-signed`
- Swift subpackage build: `cd Swift && swift build`
- Swift subpackage tests: `cd Swift && swift test`
- API compatibility: `cd Swift && ./check-api-compatibility.sh`
- Release artifact check: `cd Swift && ./build-release-apple-silicon.sh`
- pywebtransport interop: `cd Swift && ./run-pywebtransport-interop.sh`
- third-party interop: `cd Swift && ./run-third-party-interop.sh`
- VPS interop: `cd Swift && ./run-vps-third-party-interop.sh`
- Configured external interop: `cd Swift && ./run-external-interop.sh`

No dedicated lint, formatter, database migration, Docker, or production deploy command was detected.

For active Swift code changes, prefer: build, test, both CLI conformance suites, then targeted interop/release checks when relevant.
