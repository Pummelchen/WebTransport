# Trust fixtures

**These keys and certificates are for tests and for nothing else.** The private keys are
committed on purpose: the certificates are regenerated from them by `make-fixtures.sh`, and
a fixture that cannot be regenerated is a fixture nobody can check. They are not secret, they
are not trusted by anything, and using one outside this test directory would be a mistake
that the directory name is meant to prevent.

| File | What it is |
| --- | --- |
| `ca-key.pem`, `ca.pem` | The CA the tests' trust bundle contains (100-year validity). |
| `other-ca-key.pem`, `other-ca.pem` | A CA the bundle does not contain, for the unknown-issuer case. |
| `leaf-key.pem` | The key all three leaves share, so one signing step produces three certificates. |
| `leaf.pem`, `leaf.der` | `CN=example.com`, signed by `ca.pem`, with `DNS:example.com,DNS:localhost`. |
| `leaf-other-host.pem`, `.der` | The same key and CA, but `DNS:other.example`, for the name-mismatch case. |
| `leaf-unknown-ca.pem`, `.der` | `CN=example.com` signed by `other-ca.pem`, for the unknown-issuer case. |

The certificates' validity is a hundred years so that a fixture cannot expire into a
suddenly failing test. The one expiry case in the suite is deliberately not a fixture: it is
RFC 8448's own certificate, which expired on 30 July 2026, so the check is a fact about a
document rather than about the machine's clock.

`make-fixtures.sh` regenerates everything from the committed keys. It needs the `openssl`
command line, and it is run by hand when a fixture needs to change -- the tests do not
depend on it, because a test that cannot run without a tool the build does not depend on is
a test that quietly stops running.
