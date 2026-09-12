/* The TLS 1.3 key schedule and transcript, against RFC 8448 section 3.
 *
 * RFC 8448 prints one complete handshake with every intermediate value of the
 * schedule beside the inputs it came from, and it prints the handshake messages
 * themselves. That makes two kinds of test possible, and this file is both:
 *
 *   - every secret, traffic key and Finished value is compared with the RFC's own
 *     bytes, so a derivation that is wrong in any way fails here rather than
 *     producing a Finished that verifies against nothing;
 *   - the transcript is built from the RFC's handshake messages and its hash is
 *     compared with the hash the schedule says it used, which is what checks that
 *     the transcript absorbs the right bytes -- a secret can only match the RFC's
 *     if both the derivation and the hash it consumed are right.
 *
 * The vector extractor re-derives all of this from the RFC text before it writes
 * anything, so a value read from the wrong place in the trace fails generation
 * instead of making a test pass. See tests/vectors/extract_rfc8448_keyschedule.py.
 *
 * THE NEGATIVE CASES ARE THE HALF THE VECTORS CANNOT COVER. A schedule that accepted
 * an all-zero shared secret, a Finished with one byte flipped, or a handshake message
 * whose framing disagrees with its length would pass every vector here, because the
 * RFC's trace contains none of those.
 */

#include "wt_test.h"

#include "webtransport/tls/keyschedule.h"

#include "rfc8448_vectors.h"

/* The messages of RFC 8448 section 3, in transcript order. */
static const struct {
  const uint8_t *bytes;
  size_t len;
} WT_TRANSCRIPT_ORDER[] = {
    {WT_RFC8448_CLIENT_HELLO, WT_RFC8448_CLIENT_HELLO_LEN},
    {WT_RFC8448_SERVER_HELLO, WT_RFC8448_SERVER_HELLO_LEN},
    {WT_RFC8448_ENCRYPTED_EXTENSIONS, WT_RFC8448_ENCRYPTED_EXTENSIONS_LEN},
    {WT_RFC8448_CERTIFICATE, WT_RFC8448_CERTIFICATE_LEN},
    {WT_RFC8448_CERTIFICATE_VERIFY, WT_RFC8448_CERTIFICATE_VERIFY_LEN},
    {WT_RFC8448_SERVER_FINISHED_MESSAGE, WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN},
    {WT_RFC8448_CLIENT_FINISHED_MESSAGE, WT_RFC8448_CLIENT_FINISHED_MESSAGE_LEN},
};

#define WT_TRANSCRIPT_MESSAGES \
  (sizeof(WT_TRANSCRIPT_ORDER) / sizeof(WT_TRANSCRIPT_ORDER[0]))

/* Absorb the trace's messages in [from, to), in order. A transcript absorbs each
 * message once, so the calls below move a cursor through the trace rather than
 * re-absorbing its beginning. */
static void absorb(wt_tls13_transcript_t *transcript, size_t from, size_t to) {
  size_t i;
  for (i = from; i < to && i < WT_TRANSCRIPT_MESSAGES; i++) {
    if (wt_tls13_transcript_append(transcript, WT_TRANSCRIPT_ORDER[i].bytes,
                                   WT_TRANSCRIPT_ORDER[i].len) != WT_OK) {
      WT_EXPECT_TRUE("a handshake message was absorbed", 0);
      return;
    }
  }
}

static void test_extract_chain(void) {
  uint8_t early[WT_TLS13_SECRET_LEN];
  uint8_t handshake[WT_TLS13_SECRET_LEN];
  uint8_t master[WT_TLS13_SECRET_LEN];
  uint8_t derived[WT_TLS13_SECRET_LEN];

  /* The Early Secret of a handshake with no pre-shared key, which is HMAC over
   * Hash.length zero bytes with a salt of the same. */
  WT_EXPECT_OK("the early secret derives",
               wt_tls13_early_secret(NULL, 0U, early));
  WT_EXPECT_BYTES("and it is the RFC's", WT_RFC8448_EARLY_SECRET, early,
                  WT_TLS13_SECRET_LEN);
  /* An explicit zero-length PSK and a NULL one are the same handshake, and both
   * differ from any real PSK. */
  {
    uint8_t again[WT_TLS13_SECRET_LEN];
    WT_EXPECT_OK("an empty PSK is the same as none",
                 wt_tls13_early_secret(early, 0U, again));
    WT_EXPECT_BYTES("to the same secret", early, again, WT_TLS13_SECRET_LEN);
  }

  /* The "derived" step between the extracts, whose output RFC 8448 prints both as a
   * derivation and as the salt of the extract below it. */
  WT_EXPECT_OK("the derived step", wt_tls13_derived(early, derived));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_DERIVED_FOR_HANDSHAKE, derived,
                  WT_TLS13_SECRET_LEN);
  /* The next secret can only match the RFC's if this one did, because the extract's
   * salt is this value. */
  WT_EXPECT_OK("the handshake secret derives",
               wt_tls13_handshake_secret(early, WT_RFC8448_ECDHE,
                                         WT_RFC8448_ECDHE_LEN, handshake));
  WT_EXPECT_BYTES("and it is the RFC's", WT_RFC8448_HANDSHAKE_SECRET, handshake,
                  WT_TLS13_SECRET_LEN);

  WT_EXPECT_OK("the derived step for the master secret",
               wt_tls13_derived(handshake, derived));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_DERIVED_FOR_MASTER, derived,
                  WT_TLS13_SECRET_LEN);
  WT_EXPECT_OK("the master secret derives",
               wt_tls13_master_secret(handshake, master));
  WT_EXPECT_BYTES("and it is the RFC's", WT_RFC8448_MASTER_SECRET, master,
                  WT_TLS13_SECRET_LEN);

  /* A different ECDHE gives a different handshake secret: this is the input the
   * whole connection's keys hang from, so it must reach the derivation. */
  {
    uint8_t other_ecdhe[WT_RFC8448_ECDHE_LEN];
    uint8_t other[WT_TLS13_SECRET_LEN];
    memcpy(other_ecdhe, WT_RFC8448_ECDHE, sizeof(other_ecdhe));
    other_ecdhe[0] ^= 0x01U;
    WT_EXPECT_OK("another shared secret",
                 wt_tls13_handshake_secret(early, other_ecdhe, sizeof(other_ecdhe),
                                           other));
    WT_EXPECT_INT("gives another handshake secret", 0,
                  memcmp(other, handshake, WT_TLS13_SECRET_LEN) == 0 ? 1 : 0);
  }

  /* An all-zero shared secret is refused: RFC 8446 section 7.4.2 makes it a
   * handshake failure, and an implementation that derived keys from it would agree
   * with a peer that never held a private key. */
  {
    uint8_t zero_ecdhe[WT_RFC8448_ECDHE_LEN];
    memset(zero_ecdhe, 0, sizeof(zero_ecdhe));
    WT_EXPECT_STATUS("an all-zero shared secret is refused", WT_ERR_PROTOCOL,
                     wt_tls13_handshake_secret(early, zero_ecdhe,
                                               sizeof(zero_ecdhe), handshake));
  }

  /* The refusals. */
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_early_secret(NULL, 0U, NULL));
  WT_EXPECT_STATUS("a NULL PSK with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_early_secret(NULL, 32U, early));
  WT_EXPECT_STATUS("a NULL early secret is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_handshake_secret(NULL, WT_RFC8448_ECDHE,
                                             WT_RFC8448_ECDHE_LEN, handshake));
  WT_EXPECT_STATUS("an empty shared secret is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_handshake_secret(early, WT_RFC8448_ECDHE, 0U,
                                             handshake));
  WT_EXPECT_STATUS("a NULL handshake secret is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_master_secret(NULL, master));
}

static void test_transcript_and_derivations(void) {
  wt_tls13_transcript_t transcript;
  uint8_t hash[WT_TLS13_SECRET_LEN];
  uint8_t early[WT_TLS13_SECRET_LEN];
  uint8_t handshake[WT_TLS13_SECRET_LEN];
  uint8_t master[WT_TLS13_SECRET_LEN];
  uint8_t client_hs[WT_TLS13_SECRET_LEN];
  uint8_t server_hs[WT_TLS13_SECRET_LEN];
  uint8_t client_ap[WT_TLS13_SECRET_LEN];
  uint8_t server_ap[WT_TLS13_SECRET_LEN];
  uint8_t out[WT_TLS13_SECRET_LEN];

  WT_EXPECT_OK("the early secret", wt_tls13_early_secret(NULL, 0U, early));
  WT_EXPECT_OK("the handshake secret",
               wt_tls13_handshake_secret(early, WT_RFC8448_ECDHE,
                                         WT_RFC8448_ECDHE_LEN, handshake));
  WT_EXPECT_OK("the master secret", wt_tls13_master_secret(handshake, master));

  WT_EXPECT_OK("a transcript starts", wt_tls13_transcript_init(&transcript));
  absorb(&transcript, 0U, 2U); /* ClientHello, ServerHello */

  /* The hash the handshake secrets are derived from, which RFC 8448 prints as the
   * context of those derivations. */
  WT_EXPECT_OK("the transcript hash after the ServerHello",
               wt_tls13_transcript_hash(&transcript, hash));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_HASH_AFTER_SERVER_HELLO, hash,
                  WT_TLS13_SECRET_LEN);

  WT_EXPECT_OK("the handshake traffic secrets derive",
               wt_tls13_handshake_traffic_secrets(handshake, hash, client_hs,
                                                  server_hs));
  WT_EXPECT_BYTES("the client's is the RFC's", WT_RFC8448_CLIENT_HANDSHAKE_SECRET,
                  client_hs, WT_TLS13_SECRET_LEN);
  WT_EXPECT_BYTES("the server's is the RFC's", WT_RFC8448_SERVER_HANDSHAKE_SECRET,
                  server_hs, WT_TLS13_SECRET_LEN);

  /* Reading the hash must not consume the transcript: the same call twice gives the
   * same answer, and more messages can still be absorbed. */
  WT_EXPECT_OK("the hash can be read twice",
               wt_tls13_transcript_hash(&transcript, out));
  WT_EXPECT_BYTES("to the same value", hash, out, WT_TLS13_SECRET_LEN);

  /* The server's Finished is over the transcript through CertificateVerify, which
   * the RFC does not print as a step hash: the transcript is read at that point and
   * the verify data compared with the RFC's, which checks the hash and the MAC
   * together. */
  absorb(&transcript, 2U, 5U); /* through CertificateVerify */
  WT_EXPECT_OK("the server's Finished verifies",
               wt_tls13_transcript_hash(&transcript, hash));
  WT_EXPECT_OK("and its verify data",
               wt_tls13_finished_verify_data(server_hs, hash, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_SERVER_FINISHED, out,
                  WT_TLS13_FINISHED_LEN);

  absorb(&transcript, 5U, 6U); /* the server's Finished */
  WT_EXPECT_OK("the transcript hash through the server's Finished",
               wt_tls13_transcript_hash(&transcript, hash));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_HASH_AFTER_SERVER_FINISHED, hash,
                  WT_TLS13_SECRET_LEN);

  WT_EXPECT_OK("the application traffic secrets derive",
               wt_tls13_application_traffic_secrets(master, hash, client_ap,
                                                    server_ap));
  WT_EXPECT_BYTES("the client's is the RFC's", WT_RFC8448_CLIENT_APPLICATION_SECRET,
                  client_ap, WT_TLS13_SECRET_LEN);
  WT_EXPECT_BYTES("the server's is the RFC's", WT_RFC8448_SERVER_APPLICATION_SECRET,
                  server_ap, WT_TLS13_SECRET_LEN);
  WT_EXPECT_OK("the exporter master secret",
               wt_tls13_exporter_master_secret(master, hash, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_EXPORTER_MASTER, out,
                  WT_TLS13_SECRET_LEN);

  /* The client's Finished is over the same transcript, with the handshake secret of
   * the client's direction. */
  WT_EXPECT_OK("the client's Finished verify data",
               wt_tls13_finished_verify_data(client_hs, hash, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_CLIENT_FINISHED, out,
                  WT_TLS13_FINISHED_LEN);
  WT_EXPECT_OK("and it verifies",
               wt_tls13_finished_check(client_hs, hash, WT_RFC8448_CLIENT_FINISHED,
                                       WT_RFC8448_CLIENT_FINISHED_LEN));

  absorb(&transcript, 6U, 7U); /* the client's Finished */
  WT_EXPECT_OK("the transcript hash through the client's Finished",
               wt_tls13_transcript_hash(&transcript, hash));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_HASH_AFTER_CLIENT_FINISHED, hash,
                  WT_TLS13_SECRET_LEN);
  WT_EXPECT_OK("the resumption master secret",
               wt_tls13_resumption_master_secret(master, hash, out));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_RESUMPTION_MASTER, out,
                  WT_TLS13_SECRET_LEN);

  /* Two handshake messages in one buffer is not one handshake message: the framing
   * check refuses it, because the alternative is a transcript that hashes bytes the
   * peer will hash as two messages. */
  {
    uint8_t concatenated[WT_RFC8448_CLIENT_HELLO_LEN + WT_RFC8448_SERVER_HELLO_LEN];
    wt_tls13_transcript_t whole;
    memcpy(concatenated, WT_RFC8448_CLIENT_HELLO, WT_RFC8448_CLIENT_HELLO_LEN);
    memcpy(concatenated + WT_RFC8448_CLIENT_HELLO_LEN, WT_RFC8448_SERVER_HELLO,
           WT_RFC8448_SERVER_HELLO_LEN);
    WT_EXPECT_OK("a second transcript starts", wt_tls13_transcript_init(&whole));
    WT_EXPECT_STATUS("two messages in one append are refused", WT_ERR_PROTOCOL,
                     wt_tls13_transcript_append(&whole, concatenated,
                                                sizeof(concatenated)));
    WT_EXPECT_U64("and nothing was absorbed", 0U, (uint64_t)whole.messages);
    wt_tls13_transcript_clear(&whole);
  }

  WT_EXPECT_U64("the transcript counted every message", 7U,
                (uint64_t)transcript.messages);
  wt_tls13_transcript_clear(&transcript);
}

static void test_traffic_keys_and_finished(void) {
  uint8_t client_hs[WT_TLS13_SECRET_LEN];
  uint8_t server_hs[WT_TLS13_SECRET_LEN];
  uint8_t client_ap[WT_TLS13_SECRET_LEN];
  uint8_t server_ap[WT_TLS13_SECRET_LEN];
  uint8_t key[WT_TLS13_KEY_LEN];
  uint8_t iv[WT_TLS13_IV_LEN];
  uint8_t finished[WT_TLS13_FINISHED_LEN];

  memcpy(client_hs, WT_RFC8448_CLIENT_HANDSHAKE_SECRET, WT_TLS13_SECRET_LEN);
  memcpy(server_hs, WT_RFC8448_SERVER_HANDSHAKE_SECRET, WT_TLS13_SECRET_LEN);
  memcpy(client_ap, WT_RFC8448_CLIENT_APPLICATION_SECRET, WT_TLS13_SECRET_LEN);
  memcpy(server_ap, WT_RFC8448_SERVER_APPLICATION_SECRET, WT_TLS13_SECRET_LEN);

  WT_EXPECT_OK("the server's handshake keys",
               wt_tls13_traffic_keys(server_hs, key, iv));
  WT_EXPECT_BYTES("the key is the RFC's", WT_RFC8448_SERVER_HANDSHAKE_KEY, key,
                  WT_TLS13_KEY_LEN);
  WT_EXPECT_BYTES("the IV is the RFC's", WT_RFC8448_SERVER_HANDSHAKE_IV, iv,
                  WT_TLS13_IV_LEN);

  WT_EXPECT_OK("the server's application keys",
               wt_tls13_traffic_keys(server_ap, key, iv));
  WT_EXPECT_BYTES("the key is the RFC's", WT_RFC8448_SERVER_APPLICATION_KEY, key,
                  WT_TLS13_KEY_LEN);
  WT_EXPECT_BYTES("the IV is the RFC's", WT_RFC8448_SERVER_APPLICATION_IV, iv,
                  WT_TLS13_IV_LEN);

  WT_EXPECT_OK("the client's handshake keys",
               wt_tls13_traffic_keys(client_hs, key, iv));
  WT_EXPECT_BYTES("the key is the RFC's", WT_RFC8448_CLIENT_HANDSHAKE_KEY, key,
                  WT_TLS13_KEY_LEN);
  WT_EXPECT_BYTES("the IV is the RFC's", WT_RFC8448_CLIENT_HANDSHAKE_IV, iv,
                  WT_TLS13_IV_LEN);

  WT_EXPECT_OK("the client's application keys",
               wt_tls13_traffic_keys(client_ap, key, iv));
  WT_EXPECT_BYTES("the key is the RFC's", WT_RFC8448_CLIENT_APPLICATION_KEY, key,
                  WT_TLS13_KEY_LEN);
  WT_EXPECT_BYTES("the IV is the RFC's", WT_RFC8448_CLIENT_APPLICATION_IV, iv,
                  WT_TLS13_IV_LEN);

  /* The two directions never share a key, which is the property that makes the
   * labels matter: the two secrets differ by one label and the keys must differ
   * with them. */
  {
    uint8_t server_key[WT_TLS13_KEY_LEN];
    uint8_t server_iv[WT_TLS13_IV_LEN];
    uint8_t client_key[WT_TLS13_KEY_LEN];
    uint8_t client_iv[WT_TLS13_IV_LEN];
    WT_EXPECT_OK("the server's application keys again",
                 wt_tls13_traffic_keys(server_ap, server_key, server_iv));
    WT_EXPECT_OK("and the client's",
                 wt_tls13_traffic_keys(client_ap, client_key, client_iv));
    WT_EXPECT_INT("whose key differs", 0,
                  memcmp(server_key, client_key, WT_TLS13_KEY_LEN) == 0 ? 1 : 0);
    WT_EXPECT_INT("and whose IV differs", 0,
                  memcmp(server_iv, client_iv, WT_TLS13_IV_LEN) == 0 ? 1 : 0);
  }

  WT_EXPECT_OK("the server's Finished key",
               wt_tls13_finished_key(server_hs, finished));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_SERVER_FINISHED_KEY, finished,
                  WT_TLS13_FINISHED_LEN);
  WT_EXPECT_OK("the client's Finished key",
               wt_tls13_finished_key(client_hs, finished));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC8448_CLIENT_FINISHED_KEY, finished,
                  WT_TLS13_FINISHED_LEN);

  /* The key update secret (RFC 8446 section 7.2). RFC 8448 prints no vector for it,
   * so what is checked is that it is the named expansion of the secret and that it is
   * not the secret: the label and the output length are the whole construction. */
  {
    uint8_t next[WT_TLS13_SECRET_LEN];
    uint8_t want[WT_TLS13_SECRET_LEN];
    WT_EXPECT_OK("the next traffic secret",
                 wt_tls13_next_traffic_secret(client_ap, next));
    WT_EXPECT_OK("is the named expansion",
                 wt_hkdf_expand_label_sha256(client_ap, WT_TLS13_SECRET_LEN,
                                             "traffic upd", NULL, 0U, want,
                                             WT_TLS13_SECRET_LEN));
    WT_EXPECT_BYTES("of the secret", want, next, WT_TLS13_SECRET_LEN);
    WT_EXPECT_INT("and is not the secret itself", 0,
                  memcmp(next, client_ap, WT_TLS13_SECRET_LEN) == 0 ? 1 : 0);
  }

  /* The refusals. */
  WT_EXPECT_STATUS("a NULL secret is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_traffic_keys(NULL, key, iv));
  WT_EXPECT_STATUS("a NULL key output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_traffic_keys(client_ap, NULL, iv));
  WT_EXPECT_STATUS("a NULL IV output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_traffic_keys(client_ap, key, NULL));
  WT_EXPECT_STATUS("a NULL Finished key output is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_finished_key(client_hs, NULL));
  WT_EXPECT_STATUS("a NULL derive-secret label is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_derive_secret(client_hs, NULL, client_hs, key));
  WT_EXPECT_STATUS("a NULL next traffic secret is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_next_traffic_secret(NULL, key));
}

static void test_finished_check(void) {
  uint8_t client_hs[WT_TLS13_SECRET_LEN];
  uint8_t hash[WT_TLS13_SECRET_LEN];
  uint8_t damaged[WT_TLS13_FINISHED_LEN];
  size_t i;

  memcpy(client_hs, WT_RFC8448_CLIENT_HANDSHAKE_SECRET, WT_TLS13_SECRET_LEN);
  memcpy(hash, WT_RFC8448_HASH_AFTER_SERVER_FINISHED, WT_TLS13_SECRET_LEN);

  WT_EXPECT_OK("the RFC's Finished verifies",
               wt_tls13_finished_check(client_hs, hash, WT_RFC8448_CLIENT_FINISHED,
                                       WT_RFC8448_CLIENT_FINISHED_LEN));

  /* Every byte of a Finished matters, and so does every bit of every byte: a
   * comparison that stopped at the first difference would pass the first of these
   * and fail the rest, which is exactly the forgery oracle a tag comparison must not
   * be. */
  for (i = 0U; i < WT_TLS13_FINISHED_LEN; i++) {
    size_t bit;
    for (bit = 0U; bit < 8U; bit++) {
      memcpy(damaged, WT_RFC8448_CLIENT_FINISHED, sizeof(damaged));
      damaged[i] ^= (uint8_t)(1U << bit);
      WT_EXPECT_STATUS("a one-bit change fails the check", WT_ERR_AUTHENTICATION,
                       wt_tls13_finished_check(client_hs, hash, damaged,
                                               sizeof(damaged)));
    }
  }

  /* A truncated Finished is refused rather than compared over fewer bytes. */
  WT_EXPECT_STATUS("a short Finished is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_finished_check(client_hs, hash,
                                           WT_RFC8448_CLIENT_FINISHED, 0U));
  WT_EXPECT_STATUS("a one-byte Finished is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_finished_check(client_hs, hash,
                                           WT_RFC8448_CLIENT_FINISHED, 1U));
  WT_EXPECT_STATUS("a long Finished is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_finished_check(client_hs, hash,
                                           WT_RFC8448_CLIENT_FINISHED,
                                           WT_TLS13_FINISHED_LEN + 1U));
  WT_EXPECT_STATUS("a NULL Finished is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_finished_check(client_hs, hash, NULL,
                                           WT_TLS13_FINISHED_LEN));

  /* The other direction's handshake secret does not verify this Finished, and neither
   * does the same secret against another transcript. */
  {
    uint8_t server_hs[WT_TLS13_SECRET_LEN];
    uint8_t other_hash[WT_TLS13_SECRET_LEN];
    memcpy(server_hs, WT_RFC8448_SERVER_HANDSHAKE_SECRET, WT_TLS13_SECRET_LEN);
    memcpy(other_hash, WT_RFC8448_HASH_AFTER_SERVER_HELLO, WT_TLS13_SECRET_LEN);
    WT_EXPECT_STATUS("the other direction's secret does not verify it",
                     WT_ERR_AUTHENTICATION,
                     wt_tls13_finished_check(server_hs, hash,
                                             WT_RFC8448_CLIENT_FINISHED,
                                             WT_TLS13_FINISHED_LEN));
    WT_EXPECT_STATUS("and neither does another transcript", WT_ERR_AUTHENTICATION,
                     wt_tls13_finished_check(client_hs, other_hash,
                                             WT_RFC8448_CLIENT_FINISHED,
                                             WT_TLS13_FINISHED_LEN));
  }
}

static void test_transcript_refusals(void) {
  wt_tls13_transcript_t transcript;
  uint8_t hash[WT_TLS13_SECRET_LEN];
  uint8_t truncated[8];
  uint8_t wrong_length[WT_RFC8448_SERVER_HELLO_LEN];

  /* An uninitialised transcript is a state error, not a crash and not a hash of
   * nothing: the caller that forgot to initialise it gets one diagnosable failure
   * rather than secrets that match no peer. */
  {
    wt_tls13_transcript_t untouched;
    memset(&untouched, 0, sizeof(untouched));
    WT_EXPECT_STATUS("an uninitialised transcript cannot be hashed",
                     WT_ERR_STATE, wt_tls13_transcript_hash(&untouched, hash));
    WT_EXPECT_STATUS("nor updated", WT_ERR_STATE,
                     wt_tls13_transcript_append(&untouched, WT_RFC8448_SERVER_HELLO,
                                                WT_RFC8448_SERVER_HELLO_LEN));
    /* And a context with garbage where a marker belongs is refused too. */
    memset(&untouched, 0xAB, sizeof(untouched));
    WT_EXPECT_STATUS("nor a context that was never initialised",
                     WT_ERR_STATE, wt_tls13_transcript_hash(&untouched, hash));
  }

  WT_EXPECT_OK("a transcript starts", wt_tls13_transcript_init(&transcript));

  /* A message whose header length is not its size. This is the mistake the transcript
   * exists to catch: absorbing such a message would produce a hash that is not the
   * peer's, and every secret derived from it would be wrong. */
  memcpy(wrong_length, WT_RFC8448_SERVER_HELLO, sizeof(wrong_length));
  wrong_length[3] = (uint8_t)(wrong_length[3] + 1U);
  WT_EXPECT_STATUS("a message whose length disagrees is refused",
                   WT_ERR_PROTOCOL,
                   wt_tls13_transcript_append(&transcript, wrong_length,
                                              sizeof(wrong_length)));
  WT_EXPECT_U64("and nothing was absorbed", 0U, (uint64_t)transcript.messages);

  /* Fewer bytes than a handshake header. */
  memcpy(truncated, WT_RFC8448_SERVER_HELLO, sizeof(truncated));
  WT_EXPECT_STATUS("three bytes are not a handshake message", WT_ERR_TRUNCATED,
                   wt_tls13_transcript_append(&transcript, truncated, 3U));
  /* Eight bytes are a header and part of a body, which the framing check refuses
   * because the declared length is not the buffer's. */
  WT_EXPECT_STATUS("a partial body is refused", WT_ERR_PROTOCOL,
                   wt_tls13_transcript_append(&transcript, truncated,
                                              sizeof(truncated)));
  WT_EXPECT_STATUS("a NULL message is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_transcript_append(&transcript, NULL, 4U));
  WT_EXPECT_STATUS("a NULL transcript is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls13_transcript_append(NULL, truncated, sizeof(truncated)));

  /* A cleared transcript is unusable and holds nothing. */
  WT_EXPECT_OK("the ServerHello is absorbed",
               wt_tls13_transcript_append(&transcript, WT_RFC8448_SERVER_HELLO,
                                          WT_RFC8448_SERVER_HELLO_LEN));
  wt_tls13_transcript_clear(&transcript);
  WT_EXPECT_STATUS("a cleared transcript cannot be hashed", WT_ERR_STATE,
                   wt_tls13_transcript_hash(&transcript, hash));
  WT_EXPECT_STATUS("nor appended to", WT_ERR_STATE,
                   wt_tls13_transcript_append(&transcript, WT_RFC8448_SERVER_HELLO,
                                              WT_RFC8448_SERVER_HELLO_LEN));
  WT_EXPECT_TRUE("and holds no message count",
                 transcript.messages == 0UL);
  wt_tls13_transcript_clear(NULL);
  WT_EXPECT_INT("clearing NULL is harmless", 1, 1);
}

int main(void) {
  WT_EXPECT_OK("the crypto backend initialises", wt_crypto_init());

  test_extract_chain();
  test_transcript_and_derivations();
  test_traffic_keys_and_finished();
  test_finished_check();
  test_transcript_refusals();

  WT_TEST_MAIN_END("wt_tls13_keyschedule");
}
