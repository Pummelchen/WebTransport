/* QUIC packet protection, against RFC 9001 appendix A.
 *
 * Appendix A prints three complete protected packets and every value that went
 * into producing them: the Initial secrets, the keys, the header protection
 * samples and masks, the packet numbers and, for the short header packet, the
 * nonce. The tests here work in both directions on those bytes:
 *
 *   - the extracted protected packet is taken apart -- unmask the header,
 *     reconstruct the packet number, decrypt the payload -- and the payload is
 *     compared with the RFC's;
 *   - those same parts are put back together and the result must be the RFC's
 *     packet, byte for byte.
 *
 * The second direction is what catches the mistakes the first cannot: a wrong
 * nonce, a wrong AAD or a wrong sample offset that was symmetric between the two
 * halves of this implementation would still round-trip, and would still not
 * interoperate with anything.
 *
 * THE NEGATIVE CASES ARE THE OTHER HALF OF THE VECTOR WORK. A tag that does not
 * verify must be refused, and the plaintext must be gone when it is: the whole
 * point of decrypting inside one call is that no caller can be handed bytes whose
 * tag failed. So every refusal below is checked twice -- once for the status and
 * once for the cleared buffer.
 *
 * The mask widths are the one place where RFC 9001's own vectors are not enough.
 * Both AES masks in the appendix happen to have a zero in the bit that tells a
 * four-bit mask from a five-bit one, so an implementation that used the wrong
 * width would reproduce every published packet. The last test builds packets
 * whose masks do have that bit set, which is what makes the rule testable.
 */

#include "wt_test.h"

#include "webtransport/crypto/crypto.h"
#include "webtransport/quic/packet_number.h"
#include "webtransport/quic/protection.h"

#include "rfc9001_client_initial.h"
#include "rfc9001_retry.h"
#include "rfc9001_vectors.h"
#include "test_quic_protection_retry_support.h"

/* The header lengths the appendixes print, and the offsets they imply. Both
 * Initial packets put the packet number at 18 and the sample at 22; the short
 * header packet has an empty connection ID, so its number is at 1 and its sample
 * at 5. The test recomputes them from the headers rather than trusting these,
 * and uses these names only to say what the numbers mean. */

/* The destination connection ID the appendixes derive their Initial keys from.
 * It is named in a sentence rather than printed as a block, so the tests read it
 * from the packet that carries it: A.2's client Initial header has it at offset
 * 6, behind the connection ID length. */

/* The client's Initial keys, which almost every test needs. Returns WT_OK or the
 * failure, so that a broken derivation shows up as one failed check rather than
 * as a crash in the test. */

static void test_initial_keys(void) {
  uint8_t secret[WT_SHA256_LEN];
  uint8_t other_secret[WT_SHA256_LEN];
  wt_quic_packet_keys_t client;
  wt_quic_packet_keys_t server;
  const uint8_t *dcid = WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN + DCID_OFFSET;

  WT_EXPECT_U64("the version-1 salt is twenty bytes", 20U,
                (uint64_t)sizeof wt_quic_initial_salt_v1);
  WT_EXPECT_OK("the Initial secret derives",
               wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1, dcid,
                                      DCID_LEN, secret));
  WT_EXPECT_BYTES("and it is the RFC's", WT_RFC9001_INITIAL_SECRET, secret, WT_SHA256_LEN);

  /* The salt is checked by that derivation and not by a copy of its bytes: the
   * extractor re-derived the RFC's Initial secret from the same twenty bytes, so
   * a salt that differed anywhere would produce a different secret here. */
  WT_EXPECT_OK("the client keys derive",
               wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM, &client));
  WT_EXPECT_BYTES("the client key is the RFC's", WT_RFC9001_CLIENT_INITIAL_KEY, client.key,
                  WT_RFC9001_CLIENT_INITIAL_KEY_LEN);
  WT_EXPECT_BYTES("the client IV is the RFC's", WT_RFC9001_CLIENT_INITIAL_IV, client.iv,
                  WT_RFC9001_CLIENT_INITIAL_IV_LEN);
  WT_EXPECT_BYTES("the client header protection key is the RFC's", WT_RFC9001_CLIENT_INITIAL_HP,
                  client.hp, WT_RFC9001_CLIENT_INITIAL_HP_LEN);
  WT_EXPECT_BYTES("and the secret is kept for a key update", WT_RFC9001_CLIENT_INITIAL_SECRET,
                  client.secret, WT_SHA256_LEN);
  WT_EXPECT_U64("an AES key is sixteen bytes", 16U, (uint64_t)client.key_len);
  WT_EXPECT_U64("and so is its header protection key", 16U, (uint64_t)client.hp_len);
  WT_EXPECT_U64("with the suite recorded", (uint64_t)WT_AEAD_AES_128_GCM, (uint64_t)client.aead);

  WT_EXPECT_OK("the server keys derive",
               wt_quic_initial_packet_keys(secret, 1, WT_AEAD_AES_128_GCM, &server));
  WT_EXPECT_BYTES("the server key is the RFC's", WT_RFC9001_SERVER_INITIAL_KEY, server.key,
                  WT_RFC9001_SERVER_INITIAL_KEY_LEN);
  WT_EXPECT_BYTES("the server IV is the RFC's", WT_RFC9001_SERVER_INITIAL_IV, server.iv,
                  WT_RFC9001_SERVER_INITIAL_IV_LEN);
  WT_EXPECT_BYTES("the server header protection key is the RFC's", WT_RFC9001_SERVER_INITIAL_HP,
                  server.hp, WT_RFC9001_SERVER_INITIAL_HP_LEN);
  /* The two directions of one connection must not share a key: that is what
   * using the wrong label would do, and the two would still interoperate with
   * themselves. */
  WT_EXPECT_INT("the two directions have different keys", 0,
                memcmp(client.key, server.key, 16U) == 0 ? 1 : 0);

  /* The traffic-secret path and the Initial path must agree where they overlap,
   * because both are the same three labels. */
  {
    wt_quic_packet_keys_t same;
    WT_EXPECT_OK("the client secret produces the same keys",
                 wt_quic_packet_keys_from_secret(WT_RFC9001_CLIENT_INITIAL_SECRET,
                                                 WT_AEAD_AES_128_GCM, &same));
    WT_EXPECT_BYTES("the key", client.key, same.key, 16U);
    WT_EXPECT_BYTES("the IV", client.iv, same.iv, 12U);
    WT_EXPECT_BYTES("the header protection key", client.hp, same.hp, 16U);
  }

  /* The other suite: a 32-byte key and header protection key, and different
   * bytes, because the key length is an input to the expansion and not a
   * truncation of a longer one. */
  {
    wt_quic_packet_keys_t chacha;
    WT_EXPECT_OK("ChaCha20 keys derive from the Initial secret",
                 wt_quic_initial_packet_keys(secret, 0, WT_AEAD_CHACHA20_POLY1305, &chacha));
    WT_EXPECT_U64("a 32-byte key", 32U, (uint64_t)chacha.key_len);
    WT_EXPECT_U64("a 32-byte header protection key", 32U, (uint64_t)chacha.hp_len);
    WT_EXPECT_INT("which is not the AES key padded", 0,
                  memcmp(chacha.key, client.key, 16U) == 0 ? 1 : 0);
  }

  /* Two connections with different destination connection IDs have different
   * Initial keys: that is the whole reason the ID is in the derivation. */
  {
    uint8_t other_dcid[DCID_LEN];
    wt_quic_packet_keys_t other;
    memcpy(other_dcid, dcid, DCID_LEN);
    other_dcid[0] ^= 0x01U;
    WT_EXPECT_OK("another connection's Initial secret",
                 wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1,
                                        other_dcid, DCID_LEN, other_secret));
    WT_EXPECT_OK("and its client keys",
                 wt_quic_initial_packet_keys(other_secret, 0, WT_AEAD_AES_128_GCM, &other));
    WT_EXPECT_INT("which differ from this connection's", 0,
                  memcmp(other.key, client.key, 16U) == 0 ? 1 : 0);
  }

  /* An empty connection ID is legal (RFC 9000 section 5.1) and must derive
   * rather than be refused. */
  WT_EXPECT_OK("an empty connection ID is allowed",
               wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1, NULL,
                                      0U, other_secret));

  /* The refusals. */
  WT_EXPECT_STATUS("a NULL salt is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_secret(NULL, 20U, dcid, DCID_LEN, secret));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1,
                                          dcid, DCID_LEN, NULL));
  WT_EXPECT_STATUS("a NULL ID with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1,
                                          NULL, DCID_LEN, secret));
  WT_EXPECT_STATUS("a NULL Initial secret is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_packet_keys(NULL, 0, WT_AEAD_AES_128_GCM, &client));
  WT_EXPECT_STATUS("a NULL key set is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM, NULL));
  WT_EXPECT_STATUS("an unknown suite is refused", WT_ERR_UNSUPPORTED,
                   wt_quic_initial_packet_keys(secret, 0, (wt_aead_t)99, &client));
  WT_EXPECT_STATUS("a NULL traffic secret is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_keys_from_secret(NULL, WT_AEAD_AES_128_GCM, &client));

  /* Clearing a key set leaves nothing behind, which is what a discarded key
   * needs; clearing NULL must leave the live set alone rather than reach it. */
  wt_quic_packet_keys_clear(NULL);
  WT_EXPECT_TRUE("clearing NULL leaves the live key set intact",
                 !all_zero((const uint8_t *)&client, sizeof client));
  wt_quic_packet_keys_clear(&client);
  WT_EXPECT_TRUE("a cleared key set is all zeroes",
                 all_zero((const uint8_t *)&client, sizeof client));

  /* The key update: the next secret is the RFC's `ku`, and the keys are derived
   * from it with the same three labels. */
  {
    wt_quic_packet_keys_t current;
    wt_quic_packet_keys_t next;
    wt_quic_packet_keys_t again;
    uint8_t want[32];
    WT_EXPECT_OK("the ChaCha20 keys", chacha_keys(&current));
    WT_EXPECT_OK("the key update derives", wt_quic_packet_keys_update(&current, &next));
    WT_EXPECT_BYTES("and the next secret is the RFC's ku", WT_RFC9001_CHACHA_KEY_UPDATE,
                    next.secret, 32U);
    WT_EXPECT_OK("its key", wt_hkdf_expand_label_sha256(WT_RFC9001_CHACHA_KEY_UPDATE, 32U,
                                                        "quic key", NULL, 0U, want, 32U));
    WT_EXPECT_BYTES("is the derived one", want, next.key, 32U);
    WT_EXPECT_OK("its IV", wt_hkdf_expand_label_sha256(WT_RFC9001_CHACHA_KEY_UPDATE, 32U, "quic iv",
                                                       NULL, 0U, want, 12U));
    WT_EXPECT_BYTES("is the derived one", want, next.iv, 12U);
    /* RFC 9001 section 6.1: "The header protection key is not updated." The next set's hp is the CURRENT set's,
     * byte for byte -- the assertion here used to derive "quic hp" from the next secret and require that, which is
     * the rule for the key and the IV and is explicitly NOT the rule for the header protection key. The old
     * expectation is what let the public function get it wrong while its only in-tree caller patched over it. */
    WT_EXPECT_BYTES("while the header protection key is NOT updated", current.hp, next.hp,
                    sizeof(current.hp));
    WT_EXPECT_INT("and its length comes with it", (long)current.hp_len, (long)next.hp_len);
    /* The key and the IV ARE new, so the copy above is not "nothing changed". */
    WT_EXPECT_TRUE("the AEAD key did change",
                   memcmp(current.key, next.key, sizeof(current.key)) != 0);
    WT_EXPECT_U64("the suite does not change across an update", (uint64_t)WT_AEAD_CHACHA20_POLY1305,
                  (uint64_t)next.aead);
    WT_EXPECT_INT("the next secret is not the current one", 0,
                  memcmp(next.secret, current.secret, 32U) == 0 ? 1 : 0);
    WT_EXPECT_OK("and updating again is deterministic",
                 wt_quic_packet_keys_update(&current, &again));
    WT_EXPECT_BYTES("to the same secret", next.secret, again.secret, 32U);
    WT_EXPECT_STATUS("a NULL current key set is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_packet_keys_update(NULL, &next));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_packet_keys_update(&current, NULL));
  }
}

static void test_header_protection_vectors(void) {
  uint8_t sample[16];
  uint8_t mask[5];
  uint8_t short_packet[19];
  wt_quic_packet_keys_t client;
  wt_quic_packet_keys_t server;
  wt_quic_packet_keys_t chacha;

  WT_EXPECT_OK("the client Initial keys", client_initial_keys(&client));
  WT_EXPECT_OK("the server Initial keys", server_initial_keys(&server));
  WT_EXPECT_OK("the ChaCha20 keys", chacha_keys(&chacha));

  /* The client Initial packet. */
  WT_EXPECT_OK("the client sample", wt_quic_header_protection_sample(
                                        CLIENT_INITIAL_PN_OFFSET, WT_RFC9001_CLIENT_INITIAL_PACKET,
                                        WT_RFC9001_CLIENT_INITIAL_PACKET_LEN, sample));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_CLIENT_INITIAL_SAMPLE, sample, 16U);
  WT_EXPECT_OK("the client mask", wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp,
                                                                 client.hp_len, sample, mask));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_CLIENT_INITIAL_MASK, mask, 5U);

  /* The server Initial packet: the same offset, a two-byte packet number. */
  WT_EXPECT_OK("the server sample", wt_quic_header_protection_sample(
                                        SERVER_INITIAL_PN_OFFSET, WT_RFC9001_SERVER_INITIAL_PACKET,
                                        WT_RFC9001_SERVER_INITIAL_PACKET_LEN, sample));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_SERVER_INITIAL_SAMPLE, sample, 16U);
  WT_EXPECT_OK("the server mask", wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, server.hp,
                                                                 server.hp_len, sample, mask));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_SERVER_INITIAL_MASK, mask, 5U);

  /* The short header packet: an empty connection ID, so offset 1, and the
   * ChaCha20 mask, which is a keystream and not an encrypted block. */
  WT_EXPECT_OK("the ChaCha20 sample",
               wt_quic_header_protection_sample(CHACHA_PN_OFFSET, WT_RFC9001_CHACHA_PACKET,
                                                WT_RFC9001_CHACHA_PACKET_LEN, sample));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_CHACHA_SAMPLE, sample, 16U);
  WT_EXPECT_OK("the ChaCha20 mask",
               wt_quic_header_protection_mask(WT_AEAD_CHACHA20_POLY1305, chacha.hp, chacha.hp_len,
                                              sample, mask));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_CHACHA_MASK, mask, 5U);
  /* The ChaCha20 counter comes from the sample's first four bytes, so a mask
   * that were an AES encryption of the sample would not be this one; and the two
   * masks genuinely differ, which is what makes the dispatch observable. */
  WT_EXPECT_INT("the ChaCha20 mask is not the AES mask", 0,
                memcmp(mask, WT_RFC9001_CLIENT_INITIAL_MASK, 5U) == 0 ? 1 : 0);

  /* The refusals. A packet too short to hold a sample cannot be protected at
   * all: 19 bytes leaves one byte fewer than the sixteen needed after the
   * sample offset of 4. */
  memset(short_packet, 0, sizeof(short_packet));
  WT_EXPECT_STATUS(
      "a packet too short to sample is refused", WT_ERR_TRUNCATED,
      wt_quic_header_protection_sample(0U, short_packet, sizeof(short_packet), sample));
  WT_EXPECT_STATUS("an offset past the packet is refused", WT_ERR_TRUNCATED,
                   wt_quic_header_protection_sample(WT_RFC9001_CLIENT_INITIAL_PACKET_LEN,
                                                    WT_RFC9001_CLIENT_INITIAL_PACKET,
                                                    WT_RFC9001_CLIENT_INITIAL_PACKET_LEN, sample));
  WT_EXPECT_STATUS("a NULL packet is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_header_protection_sample(0U, NULL, 16U, sample));
  WT_EXPECT_STATUS("a NULL sample is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_header_protection_sample(0U, WT_RFC9001_CLIENT_INITIAL_PACKET,
                                                    WT_RFC9001_CLIENT_INITIAL_PACKET_LEN, NULL));
  WT_EXPECT_STATUS(
      "a header protection key that is too short is refused", WT_ERR_INVALID_ARGUMENT,
      wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp, 15U, sample, mask));
  WT_EXPECT_STATUS(
      "a NULL mask output is refused", WT_ERR_INVALID_ARGUMENT,
      wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp, client.hp_len, sample, NULL));
  WT_EXPECT_STATUS("an unknown suite is refused", WT_ERR_UNSUPPORTED,
                   wt_quic_header_protection_mask((wt_aead_t)99, client.hp, 32U, sample, mask));
}

static void test_client_initial_packet(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
  uint8_t aad[CLIENT_INITIAL_HEADER_LEN];
  size_t pn_len = 0U;
  const size_t payload_len =
      WT_RFC9001_CLIENT_INITIAL_PACKET_LEN - CLIENT_INITIAL_HEADER_LEN - WT_AEAD_TAG_LEN;

  WT_EXPECT_OK("the client Initial keys", client_initial_keys(&keys));
  /* The payload the RFC prints is exactly the room the packet leaves after its
   * header and tag, which is the first sign that the offsets are right. */
  WT_EXPECT_U64("the packet's payload is the RFC's payload", 1162U, (uint64_t)payload_len);
  WT_EXPECT_U64("and the payload vector says so", (uint64_t)WT_RFC9001_CLIENT_INITIAL_PAYLOAD_LEN,
                (uint64_t)payload_len);

  memcpy(packet, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(packet));
  WT_EXPECT_OK("the client header unprotects",
               wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, packet,
                                        sizeof(packet), CLIENT_INITIAL_PN_OFFSET, &pn_len));
  WT_EXPECT_U64("revealing a four-byte packet number", 4U, (uint64_t)pn_len);
  WT_EXPECT_BYTES("and the header is the RFC's unprotected header",
                  WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN, packet, CLIENT_INITIAL_HEADER_LEN);
  WT_EXPECT_U64("with the RFC's packet number", (uint64_t)CLIENT_INITIAL_PN,
                read_be(packet + CLIENT_INITIAL_PN_OFFSET, 4U));
  memcpy(aad, packet, CLIENT_INITIAL_HEADER_LEN);

  WT_EXPECT_OK("the client payload decrypts",
               wt_quic_unprotect_frames(&keys, CLIENT_INITIAL_PN, aad, CLIENT_INITIAL_HEADER_LEN,
                                        packet + CLIENT_INITIAL_HEADER_LEN, payload_len,
                                        packet + CLIENT_INITIAL_TAG_OFFSET));
  WT_EXPECT_BYTES("to the RFC's payload", WT_RFC9001_CLIENT_INITIAL_PAYLOAD,
                  packet + CLIENT_INITIAL_HEADER_LEN, payload_len);

  /* Re-protecting the parts must reproduce the packet the RFC prints: the nonce,
   * the AAD, the sample and both masks all have to be right for this to hold. */
  {
    uint8_t rebuilt[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
    size_t out_len = 0U;
    memcpy(rebuilt, aad, CLIENT_INITIAL_HEADER_LEN);
    WT_EXPECT_OK("the payload protects",
                 wt_quic_protect_frames(&keys, CLIENT_INITIAL_PN, aad, CLIENT_INITIAL_HEADER_LEN,
                                        packet + CLIENT_INITIAL_HEADER_LEN, payload_len,
                                        rebuilt + CLIENT_INITIAL_HEADER_LEN,
                                        sizeof(rebuilt) - CLIENT_INITIAL_HEADER_LEN, &out_len));
    WT_EXPECT_U64("to the payload plus a tag", (uint64_t)(payload_len + 16U), (uint64_t)out_len);
    WT_EXPECT_OK("the header protects",
                 wt_quic_protect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, rebuilt,
                                        sizeof(rebuilt), CLIENT_INITIAL_PN_OFFSET, pn_len));
    WT_EXPECT_BYTES("and the packet is the RFC's", WT_RFC9001_CLIENT_INITIAL_PACKET, rebuilt,
                    sizeof(rebuilt));
  }

  /* The AAD is the UNPROTECTED header. Using the header as it arrived on the
   * wire is the "decrypt before removing header protection" bug, and it must
   * fail rather than produce a payload. */
  {
    uint8_t copy[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
    uint8_t protected_header[CLIENT_INITIAL_HEADER_LEN];
    memcpy(copy, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(copy));
    memcpy(protected_header, copy, CLIENT_INITIAL_HEADER_LEN);
    WT_EXPECT_STATUS("the protected header as AAD is refused", WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(&keys, CLIENT_INITIAL_PN, protected_header,
                                              CLIENT_INITIAL_HEADER_LEN,
                                              copy + CLIENT_INITIAL_HEADER_LEN, payload_len,
                                              copy + CLIENT_INITIAL_TAG_OFFSET));
    WT_EXPECT_TRUE("and the plaintext is cleared",
                   all_zero(copy + CLIENT_INITIAL_HEADER_LEN, payload_len));
  }

  /* A damaged tag, and a damaged tag byte at the far end of the tag: the
   * comparison covers all sixteen bytes, not the first. */
  {
    uint8_t copy[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
    size_t i;
    for (i = 0U; i < 2U; i++) {
      size_t damage = (i == 0U) ? 0U : WT_AEAD_TAG_LEN - 1U;
      memcpy(copy, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(copy));
      WT_EXPECT_OK("the header unprotects for the tag test",
                   wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                                            sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
      copy[CLIENT_INITIAL_TAG_OFFSET + damage] ^= 0x80U;
      WT_EXPECT_STATUS("a damaged tag is refused", WT_ERR_AUTHENTICATION,
                       wt_quic_unprotect_frames(&keys, CLIENT_INITIAL_PN, copy,
                                                CLIENT_INITIAL_HEADER_LEN,
                                                copy + CLIENT_INITIAL_HEADER_LEN, payload_len,
                                                copy + CLIENT_INITIAL_TAG_OFFSET));
      WT_EXPECT_TRUE("and the plaintext is cleared",
                     all_zero(copy + CLIENT_INITIAL_HEADER_LEN, payload_len));
    }
  }

  /* A damaged ciphertext byte. */
  {
    uint8_t copy[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
    memcpy(copy, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(copy));
    WT_EXPECT_OK("the header unprotects for the ciphertext test",
                 wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                                          sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
    copy[CLIENT_INITIAL_HEADER_LEN + 1U] ^= 0x01U;
    WT_EXPECT_STATUS("a damaged ciphertext is refused", WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(&keys, CLIENT_INITIAL_PN, copy,
                                              CLIENT_INITIAL_HEADER_LEN,
                                              copy + CLIENT_INITIAL_HEADER_LEN, payload_len,
                                              copy + CLIENT_INITIAL_TAG_OFFSET));
    WT_EXPECT_TRUE("and the plaintext is cleared",
                   all_zero(copy + CLIENT_INITIAL_HEADER_LEN, payload_len));
  }

  /* The wrong packet number, which is what a receiver with a stale largest
   * acknowledged number would use, and the other direction's keys. */
  {
    uint8_t copy[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
    wt_quic_packet_keys_t server;
    memcpy(copy, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(copy));
    WT_EXPECT_OK("the header unprotects for the number test",
                 wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                                          sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
    WT_EXPECT_STATUS("the wrong packet number is refused", WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(&keys, CLIENT_INITIAL_PN + 1U, copy,
                                              CLIENT_INITIAL_HEADER_LEN,
                                              copy + CLIENT_INITIAL_HEADER_LEN, payload_len,
                                              copy + CLIENT_INITIAL_TAG_OFFSET));
    WT_EXPECT_TRUE("and the plaintext is cleared",
                   all_zero(copy + CLIENT_INITIAL_HEADER_LEN, payload_len));

    memcpy(copy, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(copy));
    WT_EXPECT_OK("the header unprotects for the direction test",
                 wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                                          sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
    WT_EXPECT_OK("the server Initial keys", server_initial_keys(&server));
    WT_EXPECT_STATUS("the server keys cannot read a client packet", WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(&server, CLIENT_INITIAL_PN, copy,
                                              CLIENT_INITIAL_HEADER_LEN,
                                              copy + CLIENT_INITIAL_HEADER_LEN, payload_len,
                                              copy + CLIENT_INITIAL_TAG_OFFSET));
    WT_EXPECT_TRUE("and the plaintext is cleared",
                   all_zero(copy + CLIENT_INITIAL_HEADER_LEN, payload_len));
  }

  /* The argument checks and the capacity check. */
  {
    uint8_t out[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
    size_t out_len = 0U;
    WT_EXPECT_STATUS("a NULL key set is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_unprotect_frames(NULL, CLIENT_INITIAL_PN, aad,
                                              CLIENT_INITIAL_HEADER_LEN, out, payload_len, aad));
    WT_EXPECT_STATUS("a NULL tag is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_unprotect_frames(&keys, CLIENT_INITIAL_PN, aad,
                                              CLIENT_INITIAL_HEADER_LEN, out, payload_len, NULL));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_protect_frames(&keys, CLIENT_INITIAL_PN, aad,
                                            CLIENT_INITIAL_HEADER_LEN,
                                            WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, NULL,
                                            sizeof(out), &out_len));
    WT_EXPECT_STATUS("a NULL length output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_protect_frames(
                         &keys, CLIENT_INITIAL_PN, aad, CLIENT_INITIAL_HEADER_LEN,
                         WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, out, sizeof(out), NULL));
    WT_EXPECT_STATUS("a buffer one byte too small is refused", WT_ERR_LIMIT,
                     wt_quic_protect_frames(&keys, CLIENT_INITIAL_PN, aad,
                                            CLIENT_INITIAL_HEADER_LEN,
                                            WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, out,
                                            payload_len + WT_AEAD_TAG_LEN - 1U, &out_len));
    WT_EXPECT_U64("and the length is not written on refusal", 0U, (uint64_t)out_len);
    WT_EXPECT_STATUS("a buffer exactly large enough is accepted", WT_OK,
                     wt_quic_protect_frames(&keys, CLIENT_INITIAL_PN, aad,
                                            CLIENT_INITIAL_HEADER_LEN,
                                            WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, out,
                                            payload_len + WT_AEAD_TAG_LEN, &out_len));
  }
}
int main(void) {
  test_initial_keys();
  test_header_protection_vectors();
  test_client_initial_packet();
  WT_TEST_MAIN_END("test_quic_protection");
}
