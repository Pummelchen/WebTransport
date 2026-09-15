# Security Policy

## Supported Versions

Security fixes are provided for the current `main` branch and the latest tagged release line.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| `1.3.x` | Yes |
| `1.2.x` and earlier (including `1.1.x`) | No |

## Reporting a Vulnerability

Please report security issues privately by opening a GitHub security advisory for this repository:

<https://github.com/Pummelchen/WebTransport/security/advisories/new>

Do not file public issues for vulnerabilities. Include enough detail to reproduce the issue, affected commit or version, platform, and whether the issue affects Swift package APIs, CLI tools, protocol parsing, TLS/QUIC behavior, or release artifacts.

Expected response:

- Initial acknowledgement as soon as possible.
- Triage and reproduction before public disclosure.
- Fix, tests, and release notes before disclosure when the report is valid.

## Automated Scanning

Every pull request and every push to `main` runs two blocking scans
(`.github/workflows/security-scan.yml`):

- **Secrets over the full commit history** with gitleaks. The two audited
  false-positive classes -- the test-only fixtures under
  `C99/tests/vectors/trust/` and one Swift enum label in a test -- are allowlisted
  by path and value in `.gitleaks.toml`; anything else fails the job.
- **Vulnerable dependencies and secrets** in the tree with trivy
  (`.trivy.yaml`).

**The one dependency, system OpenSSL.** The C99 library links the platform's
OpenSSL 3.x -- `find_package(OpenSSL 3.0 REQUIRED)`, `C99/CMakeLists.txt:38` -- and
does not vendor it or pin it in a lockfile, so a filesystem scan has nothing to
inventory and cannot report a CVE against it. The control for that dependency is
the platform: the build gets OpenSSL from the operating system's package
repositories, so security fixes arrive through the distributor's package updates.
Vendoring or pinning OpenSSL must arrive together with a scan that can see it.

## Sensitive Data

Reports should not include private keys, production certificates, packet captures containing secrets, or credentials. If such material is required to reproduce an issue, describe the setup first and coordinate privately.
