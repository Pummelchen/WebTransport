# PKCS#12 identity fixtures

These bundles are regression fixtures for the PKCS#12 import path. They are
committed rather than generated at test time because the failure they guard
against is specific to how a particular tool encodes an elliptic-curve key, and
generating it in CI would require that exact tool to be present and pinned.

Both were produced by the macOS system `openssl`, which is **LibreSSL 3.3.6**
(reported by `/usr/bin/openssl version`). This matters: LibreSSL writes the P-256
curve into the certificate's `SubjectPublicKeyInfo` as **explicit parameters**
(the full `prime-field, a, b, generator, order, cofactor` sequence) where
OpenSSL 3.x writes the `prime256v1` named-curve OID. macOS cannot build an
identity from the explicit form, and `SecPKCS12Import` raises an Objective-C
`NSInvalidArgumentException` instead of returning an error status.

Passphrase for both bundles: `pw`

| File | Purpose | SHA-256 |
| --- | --- | --- |
| `libressl-explicit-curve-identity.p12` | Must throw a catchable `WebTransportNetworkRuntimeError`, never terminate the process | `f7d14724fa7a3261e81be24ae0f5300b37b0de3376580aaae799b42fa44d7a8b` |
| `libressl-rsa-identity.p12` | Control: same tooling, RSA, must still resolve | `d26cb4ec34f6dfc2f8e72b063e8344d47e6793ec6b0e9ee789b4fb59415b756d` |

## Regenerating

```sh
cd Swift/Tests/WebTransportNetworkRuntimeTests/Resources

# 1. The crash fixture: EC P-256, explicit curve parameters.
/usr/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/key.pem -out /tmp/cert.pem -days 3650 -nodes -subj "/CN=Test" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
/usr/bin/openssl pkcs12 -export -out libressl-explicit-curve-identity.p12 \
  -inkey /tmp/key.pem -in /tmp/cert.pem -passout pass:pw

# 2. The control fixture: RSA, which imports cleanly.
/usr/bin/openssl req -x509 -newkey rsa:2048 \
  -keyout /tmp/rsa-key.pem -out /tmp/rsa-cert.pem -days 3650 -nodes -subj "/CN=Test" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
/usr/bin/openssl pkcs12 -export -out libressl-rsa-identity.p12 \
  -inkey /tmp/rsa-key.pem -in /tmp/rsa-cert.pem -passout pass:pw
```

The regenerated files will not be byte-identical (key material is random), so the
checksums above will change. What must not change is the behaviour the tests
assert. To confirm a regenerated crash fixture still exercises the intended path,
check that its certificate carries explicit parameters:

```sh
/usr/bin/openssl pkcs12 -in libressl-explicit-curve-identity.p12 -passin pass:pw \
  -nokeys -nodes | /usr/bin/openssl x509 -noout -text | grep -c prime-field
# Expected: 1 (explicit parameters present). A named-curve certificate reports 0.
```

Use `-nodes`, not `-noenc`: LibreSSL 3.3.6 — the very tool these fixtures came from —
does not recognise `-noenc` and exits with `unknown option`.

Note that the certificate and key are unrelated to this project's reference
identity; they exist only to drive the import path.
