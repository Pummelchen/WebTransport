#!/bin/sh
# Regenerate the certificate fixtures the trust tests validate against.
#
# The certificates are committed rather than generated at build time for one reason:
# every test that needs a valid chain would otherwise need the openssl command line, and a
# test that cannot run without a tool the build does not depend on is a test that quietly
# stops running. They are generated from the keys committed beside them, so this script
# reproduces them; the validity period is a hundred years so that a fixture does not expire
# into a failing test.
#
#   tests/vectors/trust/make-fixtures.sh
#
# The one certificate whose expiry IS tested is not here: RFC 8448's own, which expired on
# 30 July 2026 and is used to check that an expired chain is refused.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

days=36500

# The CA the bundle trusts.
openssl req -x509 -new -key ca-key.pem -out ca.pem -days "$days" \
  -subj "/CN=WebTransport C99 test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# A second CA that the bundle does not trust, for the unknown-issuer case.
openssl req -x509 -new -key other-ca-key.pem -out other-ca.pem -days "$days" \
  -subj "/CN=WebTransport C99 other CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

sign() {
  # sign <csr> <out> <ca-cert> <ca-key> <serial> <san>
  openssl x509 -req -in "$1" -out "$2" -CA "$3" -CAkey "$4" -CAcreateserial \
    -days "$days" -extfile - <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$6
EXT
}

openssl req -new -key leaf-key.pem -out leaf.csr -subj "/CN=example.com"
sign leaf.csr leaf.pem ca.pem ca-key.pem 1 "DNS:example.com,DNS:localhost"

openssl req -new -key leaf-key.pem -out leaf-other-host.csr -subj "/CN=other.example"
sign leaf-other-host.csr leaf-other-host.pem ca.pem ca-key.pem 2 "DNS:other.example"

openssl req -new -key leaf-key.pem -out leaf-unknown-ca.csr -subj "/CN=example.com"
sign leaf-unknown-ca.csr leaf-unknown-ca.pem other-ca.pem other-ca-key.pem 3 "DNS:example.com"

# The DER forms, because a certificate message carries DER and the test feeds these to the
# parser rather than converting a PEM file at run time.
for name in leaf leaf-other-host leaf-unknown-ca; do
  openssl x509 -in "$name.pem" -outform DER -out "$name.der"
done

rm -f leaf.csr leaf-other-host.csr leaf-unknown-ca.csr ca.srl other-ca.srl

echo "make-fixtures: wrote the PEM certificates, their DER forms, and the PEM bundle"
