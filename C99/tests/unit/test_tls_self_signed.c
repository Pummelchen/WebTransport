/* A self-signed identity for local development (Phase 9).
 *
 * The test is a closed loop, which is the only kind worth having for a certificate: generate the pair, pin the
 * fingerprint the generator returned, and let the TRUST LAYER decide -- first that the pin matches, and then
 * that a different pin does not. A generator tested by comparing its output with itself would prove nothing
 * about whether anything can trust it.
 */

#include "wt_test.h"

#include <string.h>

#include "webtransport/tls/self_signed.h"
#include "webtransport/tls/trust.h"

static void test_a_generated_identity_can_be_pinned(void) {
  wt_tls_self_signed_t self;
  wt_tls_server_identity_t identity;
  wt_tls_certificate_t certificate;
  wt_tls_trust_policy_t policy;
  uint8_t spki[WT_TLS_SPKI_MAX];
  size_t spki_len = 0U;
  wt_status_t status;

  WT_EXPECT_OK("a loopback identity generates", wt_tls_self_signed_generate(&self, "localhost"));
  WT_EXPECT_TRUE("with a certificate", self.certificate_len > 0U);
  WT_EXPECT_TRUE("a private key", self.private_key_len > 0U);
  WT_EXPECT_TRUE("and a fingerprint", self.fingerprint[0] != 0U || self.fingerprint[1] != 0U);

  /* The identity points INTO the generated buffers and carries the scheme the key signs with. */
  wt_tls_self_signed_identity(&self, &identity);
  WT_EXPECT_U64("the identity carries one certificate", 1U, (uint64_t)identity.certificate_count);
  WT_EXPECT_TRUE("which is the generated one", identity.certificate[0] == self.certificate);
  WT_EXPECT_U64("with the scheme an ECDSA P-256 key uses",
                (uint64_t)WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                (uint64_t)identity.signature_scheme);
  WT_EXPECT_TRUE("and the private key beside it", identity.private_key == self.private_key);

  /* The pin the generator returned is what a client uses, and the trust layer is the judge. */
  wt_tls_self_signed_certificate(&self, &certificate);
  memset(&policy, 0, sizeof(policy));
  policy.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
  policy.host_name = "localhost";
  memcpy(policy.fingerprints[0], self.fingerprint, WT_SHA256_LEN);
  policy.fingerprint_count = 1U;

  status = wt_tls_trust_verify(&policy, &certificate, spki, &spki_len);
  WT_EXPECT_OK("the trust layer accepts the certificate it pinned", status);
  WT_EXPECT_TRUE("and hands back the public key it validated", spki_len > 0U);

  /* A different pin is refused: that is the whole value of a pin. */
  policy.fingerprints[0][0] = (uint8_t)(self.fingerprint[0] ^ 0xffU);
  WT_EXPECT_STATUS("a different pin is refused", WT_ERR_TRUST,
                   wt_tls_trust_verify(&policy, &certificate, spki, &spki_len));

  /* No pin at all is refused too, rather than treated as "any certificate will do". */
  policy.fingerprint_count = 0U;
  WT_EXPECT_STATUS("and no pin at all is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_trust_verify(&policy, &certificate, spki, &spki_len));

  /* Two generations differ, which is what makes the pin worth checking rather than a constant. */
  {
    wt_tls_self_signed_t other;
    WT_EXPECT_OK("a second identity generates", wt_tls_self_signed_generate(&other, "localhost"));
    WT_EXPECT_TRUE("and it is not the same certificate",
                   other.certificate_len != self.certificate_len ||
                       memcmp(other.certificate, self.certificate, self.certificate_len) != 0);
    WT_EXPECT_TRUE("nor the same fingerprint",
                   memcmp(other.fingerprint, self.fingerprint, WT_SHA256_LEN) != 0);
  }
}

static void test_the_arguments_are_guarded(void) {
  wt_tls_self_signed_t self;

  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_self_signed_generate(NULL, "localhost"));
  WT_EXPECT_STATUS("a NULL name is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_self_signed_generate(&self, NULL));
  WT_EXPECT_STATUS("and an empty name is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_self_signed_generate(&self, ""));
  /* The helpers do nothing on NULL rather than dereferencing it: they are called from cleanup paths. */
  wt_tls_self_signed_identity(NULL, NULL);
  wt_tls_self_signed_certificate(&self, NULL);
}

int main(void) {
  test_a_generated_identity_can_be_pinned();
  test_the_arguments_are_guarded();
  WT_TEST_MAIN_END("wt_tls_self_signed");
}
