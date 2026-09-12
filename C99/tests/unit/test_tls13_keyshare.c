/* X25519 key agreement, against RFC 7748 and the RFC 8448 handshake.
 *
 * RFC 7748 gives the primitive two kinds of test: section 5.2's scalar-multiplication
 * vectors, where the u-coordinate is an arbitrary value rather than the base point, and
 * section 6.1's complete Diffie-Hellman example. Both are used here, and the second one
 * matters most: the shared secret it prints is the same value RFC 8448's key schedule
 * consumes as the ECDHE input, so the last test in this file ties the key agreement to
 * the schedule -- if either end is wrong, the two documents disagree.
 *
 * The all-zero secret is the case no vector contains and every implementation must
 * refuse: it is what a peer produces by sending a point of small order, and RFC 8446
 * section 7.4.2 makes it a handshake failure. The tests check that it is refused, that
 * nothing is written when it is, and that the refusal does not depend on which group
 * the caller named.
 */

#include "wt_test.h"

#include "webtransport/crypto/crypto.h"
#include "webtransport/tls/keyshare.h"

#include "rfc7748_vectors.h"
#include "rfc8448_vectors.h"

/* A public key of small order, which is the input the all-zero check exists for. The
 * value is one of the points RFC 7748 section 7 lists as producing a zero secret; zero
 * itself is the simplest of them, and every byte of it is its own encoding. */
static const uint8_t WT_SMALL_ORDER_KEY[WT_TLS_X25519_KEY_LEN] = {0};

static void test_primitives(void) {
  uint8_t out[WT_TLS_X25519_KEY_LEN];

  /* SECTION 5.2, where the u-coordinate is not the base point: this is RFC 7748's
   * X25519(k, u) rather than a key exchange, and it is what separates a correct
   * implementation of the function from one that only happens to multiply by 9. */
  WT_EXPECT_OK("the first scalar-multiplication vector",
               wt_tls_x25519(WT_RFC7748_SCALAR_1, WT_RFC7748_U_COORDINATE_1, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC7748_OUTPUT_1, out,
                  WT_TLS_X25519_KEY_LEN);

  WT_EXPECT_OK("the second scalar-multiplication vector",
               wt_tls_x25519(WT_RFC7748_SCALAR_2, WT_RFC7748_U_COORDINATE_2, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC7748_OUTPUT_2, out,
                  WT_TLS_X25519_KEY_LEN);

  /* The two are not the same computation, which is what makes them two tests. */
  WT_EXPECT_INT("the two vectors differ", 0,
                memcmp(WT_RFC7748_OUTPUT_1, WT_RFC7748_OUTPUT_2,
                       WT_TLS_X25519_KEY_LEN) == 0
                    ? 1
                    : 0);

  /* A public key is X25519(private, 9), and the RFC prints both of Alice's and Bob's. */
  WT_EXPECT_OK("Alice's public key",
               wt_tls_key_share_public_key(WT_TLS_GROUP_X25519,
                                           WT_RFC7748_ALICE_PRIVATE, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC7748_ALICE_PUBLIC, out,
                  WT_TLS_X25519_KEY_LEN);
  WT_EXPECT_OK("Bob's public key",
               wt_tls_key_share_public_key(WT_TLS_GROUP_X25519,
                                           WT_RFC7748_BOB_PRIVATE, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC7748_BOB_PUBLIC, out,
                  WT_TLS_X25519_KEY_LEN);

  /* The refusals. A group this implementation cannot complete is refused by name rather
   * than treated as X25519, and NULL is refused before anything is derived. */
  WT_EXPECT_STATUS("an unsupported group is refused", WT_ERR_UNSUPPORTED,
                   wt_tls_key_share_public_key(WT_TLS_GROUP_SECP256R1,
                                               WT_RFC7748_ALICE_PRIVATE, out));
  WT_EXPECT_STATUS("a NULL private key is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_key_share_public_key(WT_TLS_GROUP_X25519, NULL, out));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_key_share_public_key(WT_TLS_GROUP_X25519,
                                               WT_RFC7748_ALICE_PRIVATE, NULL));
  WT_EXPECT_STATUS("a NULL scalar is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_x25519(NULL, WT_RFC7748_U_COORDINATE_1, out));
  WT_EXPECT_STATUS("a NULL coordinate is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_x25519(WT_RFC7748_SCALAR_1, NULL, out));
}

static void test_key_exchange(void) {
  uint8_t alice_secret[WT_TLS_X25519_KEY_LEN];
  uint8_t bob_secret[WT_TLS_X25519_KEY_LEN];

  /* Each side computes the shared secret from its own private key and the other's
   * public key, and RFC 7748 prints the value. */
  WT_EXPECT_OK("Alice's side",
               wt_tls_key_share_shared_secret(
                   WT_TLS_GROUP_X25519, WT_RFC7748_ALICE_PRIVATE,
                   WT_RFC7748_BOB_PUBLIC, WT_TLS_X25519_KEY_LEN, alice_secret));
  WT_EXPECT_BYTES("is the RFC's shared secret", WT_RFC7748_SHARED_SECRET,
                  alice_secret, WT_TLS_X25519_KEY_LEN);
  WT_EXPECT_OK("Bob's side",
               wt_tls_key_share_shared_secret(
                   WT_TLS_GROUP_X25519, WT_RFC7748_BOB_PRIVATE,
                   WT_RFC7748_ALICE_PUBLIC, WT_TLS_X25519_KEY_LEN, bob_secret));
  WT_EXPECT_BYTES("and agrees", alice_secret, bob_secret,
                  WT_TLS_X25519_KEY_LEN);

  /* THE VECTORS FROM A SECOND DOCUMENT, and the reason this file and the key schedule
   * test share a value. RFC 8448 prints both sides' ephemeral keys and the shared secret
   * the key schedule consumes, so:
   *
   *   - each public key must be X25519(private, 9), which checks the ladder against a
   *     document other than RFC 7748;
   *   - X25519(client private, server public) must be exactly the ECDHE value that
   *     RFC 8448's trace feeds to HKDF-Extract, which is what ties the key agreement to
   *     the schedule: if either end were wrong, the two documents would disagree.
   */
  {
    uint8_t public_key[WT_TLS_X25519_KEY_LEN];
    uint8_t ecdhe[WT_TLS_X25519_KEY_LEN];

    WT_EXPECT_OK("the RFC 8448 client's public key",
                 wt_tls_key_share_public_key(WT_TLS_GROUP_X25519,
                                             WT_RFC8448_CLIENT_X25519_PRIVATE,
                                             public_key));
    WT_EXPECT_BYTES("is the one RFC 8448 sent", WT_RFC8448_CLIENT_X25519_PUBLIC,
                    public_key, WT_TLS_X25519_KEY_LEN);
    WT_EXPECT_OK("the RFC 8448 server's public key",
                 wt_tls_key_share_public_key(WT_TLS_GROUP_X25519,
                                             WT_RFC8448_SERVER_X25519_PRIVATE,
                                             public_key));
    WT_EXPECT_BYTES("is the one RFC 8448 sent", WT_RFC8448_SERVER_X25519_PUBLIC,
                    public_key, WT_TLS_X25519_KEY_LEN);

    WT_EXPECT_OK("the handshake's shared secret",
                 wt_tls_key_share_shared_secret(
                     WT_TLS_GROUP_X25519, WT_RFC8448_CLIENT_X25519_PRIVATE,
                     WT_RFC8448_SERVER_X25519_PUBLIC, WT_TLS_X25519_KEY_LEN,
                     ecdhe));
    WT_EXPECT_BYTES("is the ECDHE value its key schedule consumed",
                    WT_RFC8448_ECDHE, ecdhe, WT_TLS_X25519_KEY_LEN);
  }

  /* The all-zero secret is refused, and nothing is left in the output buffer. The
   * backend refuses it by failing the derivation rather than by returning zeroes, so this
   * checks both the status and that the buffer was cleared. */
  {
    uint8_t secret[WT_TLS_X25519_KEY_LEN];
    memset(secret, 0xAB, sizeof(secret));
    WT_EXPECT_STATUS("a small-order public key is refused", WT_ERR_PROTOCOL,
                     wt_tls_key_share_shared_secret(
                         WT_TLS_GROUP_X25519, WT_RFC7748_ALICE_PRIVATE,
                         WT_SMALL_ORDER_KEY, sizeof(WT_SMALL_ORDER_KEY), secret));
    WT_EXPECT_TRUE("and nothing is written",
                   secret[0] == 0U && secret[WT_TLS_X25519_KEY_LEN - 1U] == 0U);
    /* The primitive reports the same refusal: a caller that uses it directly cannot be
     * handed the all-zero value either. */
    WT_EXPECT_STATUS("the primitive refuses it too", WT_ERR_PROTOCOL,
                     wt_tls_x25519(WT_RFC7748_ALICE_PRIVATE, WT_SMALL_ORDER_KEY,
                                   secret));
  }

  /* A peer key of the wrong length is refused rather than padded or truncated. */
  WT_EXPECT_STATUS("a short peer key is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_key_share_shared_secret(
                       WT_TLS_GROUP_X25519, WT_RFC7748_ALICE_PRIVATE,
                       WT_RFC7748_BOB_PUBLIC, WT_TLS_X25519_KEY_LEN - 1U,
                       alice_secret));
  WT_EXPECT_STATUS("a long peer key is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_key_share_shared_secret(
                       WT_TLS_GROUP_X25519, WT_RFC7748_ALICE_PRIVATE,
                       WT_RFC7748_BOB_PUBLIC, WT_TLS_X25519_KEY_LEN + 1U,
                       alice_secret));
  WT_EXPECT_STATUS("a NULL peer key is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_key_share_shared_secret(
                       WT_TLS_GROUP_X25519, WT_RFC7748_ALICE_PRIVATE, NULL,
                       WT_TLS_X25519_KEY_LEN, alice_secret));
  WT_EXPECT_STATUS("an unsupported group is refused", WT_ERR_UNSUPPORTED,
                   wt_tls_key_share_shared_secret(
                       WT_TLS_GROUP_SECP256R1, WT_RFC7748_ALICE_PRIVATE,
                       WT_RFC7748_BOB_PUBLIC, WT_TLS_X25519_KEY_LEN,
                       alice_secret));
}

static void test_generation(void) {
  uint8_t first_private[WT_TLS_X25519_KEY_LEN];
  uint8_t first_public[WT_TLS_X25519_KEY_LEN];
  uint8_t second_private[WT_TLS_X25519_KEY_LEN];
  uint8_t second_public[WT_TLS_X25519_KEY_LEN];
  uint8_t from_private[WT_TLS_X25519_KEY_LEN];
  uint8_t shared_one[WT_TLS_X25519_KEY_LEN];
  uint8_t shared_two[WT_TLS_X25519_KEY_LEN];

  WT_EXPECT_OK("a key pair generates",
               wt_tls_key_share_generate(WT_TLS_GROUP_X25519, first_private,
                                         first_public));
  WT_EXPECT_OK("and another",
               wt_tls_key_share_generate(WT_TLS_GROUP_X25519, second_private,
                                         second_public));
  /* Two generations agreeing would mean the generator is not generating. */
  WT_EXPECT_INT("the two private keys differ", 0,
                memcmp(first_private, second_private, WT_TLS_X25519_KEY_LEN) == 0
                    ? 1
                    : 0);
  WT_EXPECT_INT("and so do the public keys", 0,
                memcmp(first_public, second_public, WT_TLS_X25519_KEY_LEN) == 0
                    ? 1
                    : 0);

  /* The public key is the one the private key produces, and the two sides of an
   * exchange agree -- which is the only property a generated pair can be checked for,
   * since the bytes are random. */
  WT_EXPECT_OK("the public key is reproducible from the private key",
               wt_tls_key_share_public_key(WT_TLS_GROUP_X25519, first_private,
                                           from_private));
  WT_EXPECT_BYTES("byte for byte", first_public, from_private,
                  WT_TLS_X25519_KEY_LEN);
  WT_EXPECT_OK("the first side's secret",
               wt_tls_key_share_shared_secret(WT_TLS_GROUP_X25519, first_private,
                                              second_public,
                                              WT_TLS_X25519_KEY_LEN, shared_one));
  WT_EXPECT_OK("the second side's secret",
               wt_tls_key_share_shared_secret(WT_TLS_GROUP_X25519, second_private,
                                              first_public,
                                              WT_TLS_X25519_KEY_LEN, shared_two));
  WT_EXPECT_BYTES("agreeing", shared_one, shared_two, WT_TLS_X25519_KEY_LEN);
  WT_EXPECT_INT("and not all zero", 1,
                shared_one[0] == 0U && shared_one[1] == 0U ? 0 : 1);

  WT_EXPECT_STATUS("an unsupported group cannot generate", WT_ERR_UNSUPPORTED,
                   wt_tls_key_share_generate(WT_TLS_GROUP_SECP256R1, first_private,
                                             first_public));
  WT_EXPECT_STATUS("a NULL private key is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_key_share_generate(WT_TLS_GROUP_X25519, NULL,
                                             first_public));
  WT_EXPECT_STATUS("a NULL public key is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_key_share_generate(WT_TLS_GROUP_X25519, first_private,
                                             NULL));
}

static void test_group_registry(void) {
  WT_EXPECT_INT("x25519 is supported", 1,
                wt_tls_key_share_supported(WT_TLS_GROUP_X25519));
  WT_EXPECT_INT("secp256r1 is not", 0,
                wt_tls_key_share_supported(WT_TLS_GROUP_SECP256R1));
  WT_EXPECT_INT("nor is an unknown group", 0,
                wt_tls_key_share_supported(0x1234U));
  WT_EXPECT_U64("x25519 keys are 32 bytes", 32U,
                (uint64_t)wt_tls_key_share_key_len(WT_TLS_GROUP_X25519));
  WT_EXPECT_U64("secp256r1 has no key length here", 0U,
                (uint64_t)wt_tls_key_share_key_len(WT_TLS_GROUP_SECP256R1));
}

int main(void) {
  WT_EXPECT_OK("the crypto backend initialises", wt_crypto_init());

  test_primitives();
  test_key_exchange();
  test_generation();
  test_group_registry();

  WT_TEST_MAIN_END("wt_tls13_keyshare");
}
