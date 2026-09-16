# PKCS#12 identity fixtures

These bundles are regression fixtures for the PKCS#12 import path. They are
committed rather than generated at test time because the failure they guard
against is specific to how a particular tool encodes an elliptic-curve key, and
generating it in CI would require that exact tool to be present and pinned.

Passphrase for both bundles: `pw`

| File | Purpose | SHA-256 |
| --- | --- | --- |
| `libressl-explicit-curve-identity.p12` | Must throw a catchable `WebTransportNetworkRuntimeError`, never terminate the process | `f7d14724fa7a3261e81be24ae0f5300b37b0de3376580aaae799b42fa44d7a8b` |
| `libressl-rsa-identity.p12` | Control: same tooling's RSA key material, must still resolve | `6132cde98b1d06518304116c0333e4c05c975daf5867eeedefcaf4bc83080f7d` |

## Provenance

The **key material and certificate** in both bundles were produced by the macOS
system `openssl`, which is **LibreSSL 3.3.6** (reported by
`/usr/bin/openssl version`). The file names record where that material came from,
which matters for the crash fixture: LibreSSL writes the P-256 curve into the
certificate's `SubjectPublicKeyInfo` as **explicit parameters** (the full
`prime-field, a, b, generator, order, cofactor` sequence) where OpenSSL 3.x writes
the `prime256v1` named-curve OID. macOS cannot build an identity from the
explicit form, and `SecPKCS12Import` raises an Objective-C
`NSInvalidArgumentException` instead of returning an error status.

The RSA fixture keeps that same LibreSSL-generated RSA key and certificate, but
its **container is re-encoded with OpenSSL 3** (PBES2, PBKDF2-HMAC-SHA256,
AES-256-CBC). LibreSSL's default container is `pbeWithSHA1And40BitRC2-CBC`, which
`SecPKCS12Import` refused on macOS 26 and which OpenSSL 3.x will not read without
its legacy provider — neither is a property this test is about, so the fixture no
longer depends on either. The key material, certificate and passphrase are the
ones the fixture always had; only the container encoding changed.

## Regenerating

```sh
cd Swift/Tests/WebTransportNetworkRuntimeTests/Resources

# 1. The crash fixture: EC P-256, explicit curve parameters, LibreSSL container.
#    /usr/bin/openssl is LibreSSL 3.3.6 on macOS.
/usr/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/key.pem -out /tmp/cert.pem -days 3650 -nodes -subj "/CN=Test" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
/usr/bin/openssl pkcs12 -export -out libressl-explicit-curve-identity.p12 \
  -inkey /tmp/key.pem -in /tmp/cert.pem -passout pass:pw

# 2. The control fixture: RSA, which imports cleanly. Read the existing key and
#    certificate back out, then re-encode the container with OpenSSL 3 so it does
#    not depend on the RC2-40-CBC form LibreSSL writes. Use OpenSSL 3.x here
#    (`/opt/homebrew/bin/openssl` on this host); -provider legacy is what lets it
#    read the RC2 container this fixture replaced, and is harmless for AES.
/opt/homebrew/bin/openssl pkcs12 -in libressl-rsa-identity.p12 -passin pass:pw \
  -provider default -provider legacy -clcerts -nokeys -out /tmp/rsa-cert.pem
/opt/homebrew/bin/openssl pkcs12 -in libressl-rsa-identity.p12 -passin pass:pw \
  -provider default -provider legacy -nocerts -nodes -out /tmp/rsa-key.pem
# Re-emit without the `Bag Attributes` LibreSSL prepends, so the pair is a plain
# PEM certificate and key.
/opt/homebrew/bin/openssl x509 -in /tmp/rsa-cert.pem -out /tmp/rsa-cert-clean.pem
/opt/homebrew/bin/openssl rsa -in /tmp/rsa-key.pem -out /tmp/rsa-key-clean.pem
/opt/homebrew/bin/openssl pkcs12 -export -out libressl-rsa-identity.p12 \
  -inkey /tmp/rsa-key-clean.pem -in /tmp/rsa-cert-clean.pem -passout pass:pw \
  -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg SHA256 -iter 10000
```

The regenerated files will not be byte-identical (key material and PKCS#12 salts
are random), so the checksums above will change. What must not change is the
behaviour the tests assert. To confirm a regenerated crash fixture still exercises
the intended path, check that its certificate carries explicit parameters:

```sh
/usr/bin/openssl pkcs12 -in libressl-explicit-curve-identity.p12 -passin pass:pw \
  -nokeys -nodes | /usr/bin/openssl x509 -noout -text | grep -c prime-field
# Expected: 1 (explicit parameters present). A named-curve certificate reports 0.
```

To confirm the RSA fixture is the modern container rather than the RC2 form:

```sh
/opt/homebrew/bin/openssl pkcs12 -in libressl-rsa-identity.p12 -passin pass:pw \
  -info -noout
# Expected: MAC: sha256, Iteration 10000, and PBES2/PBKDF2/AES-256-CBC/hmacWithSHA256
# for both the certificate bag and the shrouded key bag.
```

Use `-nodes`, not `-noenc`, with LibreSSL: LibreSSL 3.3.6 — the very tool the
crash fixture comes from — does not recognise `-noenc` and exits with
`unknown option`.

Note that the certificate and key are unrelated to this project's reference
identity; they exist only to drive the import path.
