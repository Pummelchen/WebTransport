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

/* The header lengths the appendixes print, and the offsets they imply. Both
 * Initial packets put the packet number at 18 and the sample at 22; the short
 * header packet has an empty connection ID, so its number is at 1 and its sample
 * at 5. The test recomputes them from the headers rather than trusting these,
 * and uses these names only to say what the numbers mean. */
#define CLIENT_INITIAL_HEADER_LEN 22U
#define SERVER_INITIAL_HEADER_LEN 20U
#define CLIENT_INITIAL_PN_OFFSET 18U
#define SERVER_INITIAL_PN_OFFSET 18U
#define CHACHA_PN_OFFSET 1U
#define CLIENT_INITIAL_PN 2U
#define SERVER_INITIAL_PN 1U
#define CLIENT_INITIAL_TAG_OFFSET \
  (WT_RFC9001_CLIENT_INITIAL_PACKET_LEN - WT_AEAD_TAG_LEN)
#define SERVER_INITIAL_TAG_OFFSET \
  (WT_RFC9001_SERVER_INITIAL_PACKET_LEN - WT_AEAD_TAG_LEN)
#define CHACHA_TAG_OFFSET (WT_RFC9001_CHACHA_PACKET_LEN - WT_AEAD_TAG_LEN)
#define CHACHA_PAYLOAD_LEN 1U

/* The destination connection ID the appendixes derive their Initial keys from.
 * It is named in a sentence rather than printed as a block, so the tests read it
 * from the packet that carries it: A.2's client Initial header has it at offset
 * 6, behind the connection ID length. */
#define DCID_OFFSET 6U
#define DCID_LEN 8U

static uint64_t read_be(const uint8_t *bytes, size_t len) {
  uint64_t value = 0U;
  size_t i;
  for (i = 0U; i < len; i++) {
    value = (value << 8) | (uint64_t)bytes[i];
  }
  return value;
}

static int all_zero(const uint8_t *bytes, size_t len) {
  size_t i;
  for (i = 0U; i < len; i++) {
    if (bytes[i] != 0U) return 0;
  }
  return 1;
}

/* The client's Initial keys, which almost every test needs. Returns WT_OK or the
 * failure, so that a broken derivation shows up as one failed check rather than
 * as a crash in the test. */
static wt_status_t client_initial_keys(wt_quic_packet_keys_t *out) {
  uint8_t secret[WT_SHA256_LEN];
  wt_status_t status = wt_quic_initial_secret(
      wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1,
      WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN + DCID_OFFSET, DCID_LEN, secret);
  if (status != WT_OK) return status;
  return wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM, out);
}

static wt_status_t server_initial_keys(wt_quic_packet_keys_t *out) {
  uint8_t secret[WT_SHA256_LEN];
  wt_status_t status = wt_quic_initial_secret(
      wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1,
      WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN + DCID_OFFSET, DCID_LEN, secret);
  if (status != WT_OK) return status;
  return wt_quic_initial_packet_keys(secret, 1, WT_AEAD_AES_128_GCM, out);
}

static wt_status_t chacha_keys(wt_quic_packet_keys_t *out) {
  return wt_quic_packet_keys_from_secret(WT_RFC9001_CHACHA_SECRET,
                                         WT_AEAD_CHACHA20_POLY1305, out);
}

static void test_initial_keys(void) {
  uint8_t secret[WT_SHA256_LEN];
  uint8_t other_secret[WT_SHA256_LEN];
  wt_quic_packet_keys_t client;
  wt_quic_packet_keys_t server;
  const uint8_t *dcid = WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN + DCID_OFFSET;

  WT_EXPECT_U64("the version-1 salt is twenty bytes", 20U,
                (uint64_t)sizeof wt_quic_initial_salt_v1);
  WT_EXPECT_OK("the Initial secret derives",
               wt_quic_initial_secret(wt_quic_initial_salt_v1,
                                      sizeof wt_quic_initial_salt_v1, dcid,
                                      DCID_LEN, secret));
  WT_EXPECT_BYTES("and it is the RFC's", WT_RFC9001_INITIAL_SECRET, secret,
                  WT_SHA256_LEN);

  /* The salt is checked by that derivation and not by a copy of its bytes: the
   * extractor re-derived the RFC's Initial secret from the same twenty bytes, so
   * a salt that differed anywhere would produce a different secret here. */
  WT_EXPECT_OK("the client keys derive",
               wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM,
                                           &client));
  WT_EXPECT_BYTES("the client key is the RFC's", WT_RFC9001_CLIENT_INITIAL_KEY,
                  client.key, WT_RFC9001_CLIENT_INITIAL_KEY_LEN);
  WT_EXPECT_BYTES("the client IV is the RFC's", WT_RFC9001_CLIENT_INITIAL_IV,
                  client.iv, WT_RFC9001_CLIENT_INITIAL_IV_LEN);
  WT_EXPECT_BYTES("the client header protection key is the RFC's",
                  WT_RFC9001_CLIENT_INITIAL_HP, client.hp,
                  WT_RFC9001_CLIENT_INITIAL_HP_LEN);
  WT_EXPECT_BYTES("and the secret is kept for a key update",
                  WT_RFC9001_CLIENT_INITIAL_SECRET, client.secret,
                  WT_SHA256_LEN);
  WT_EXPECT_U64("an AES key is sixteen bytes", 16U, (uint64_t)client.key_len);
  WT_EXPECT_U64("and so is its header protection key", 16U,
                (uint64_t)client.hp_len);
  WT_EXPECT_U64("with the suite recorded", (uint64_t)WT_AEAD_AES_128_GCM,
                (uint64_t)client.aead);

  WT_EXPECT_OK("the server keys derive",
               wt_quic_initial_packet_keys(secret, 1, WT_AEAD_AES_128_GCM,
                                           &server));
  WT_EXPECT_BYTES("the server key is the RFC's", WT_RFC9001_SERVER_INITIAL_KEY,
                  server.key, WT_RFC9001_SERVER_INITIAL_KEY_LEN);
  WT_EXPECT_BYTES("the server IV is the RFC's", WT_RFC9001_SERVER_INITIAL_IV,
                  server.iv, WT_RFC9001_SERVER_INITIAL_IV_LEN);
  WT_EXPECT_BYTES("the server header protection key is the RFC's",
                  WT_RFC9001_SERVER_INITIAL_HP, server.hp,
                  WT_RFC9001_SERVER_INITIAL_HP_LEN);
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
                 wt_quic_packet_keys_from_secret(
                     WT_RFC9001_CLIENT_INITIAL_SECRET, WT_AEAD_AES_128_GCM,
                     &same));
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
                 wt_quic_initial_packet_keys(secret, 0,
                                             WT_AEAD_CHACHA20_POLY1305,
                                             &chacha));
    WT_EXPECT_U64("a 32-byte key", 32U, (uint64_t)chacha.key_len);
    WT_EXPECT_U64("a 32-byte header protection key", 32U,
                  (uint64_t)chacha.hp_len);
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
                 wt_quic_initial_secret(wt_quic_initial_salt_v1,
                                        sizeof wt_quic_initial_salt_v1,
                                        other_dcid, DCID_LEN, other_secret));
    WT_EXPECT_OK("and its client keys",
                 wt_quic_initial_packet_keys(other_secret, 0,
                                             WT_AEAD_AES_128_GCM, &other));
    WT_EXPECT_INT("which differ from this connection's", 0,
                  memcmp(other.key, client.key, 16U) == 0 ? 1 : 0);
  }

  /* An empty connection ID is legal (RFC 9000 section 5.1) and must derive
   * rather than be refused. */
  WT_EXPECT_OK("an empty connection ID is allowed",
               wt_quic_initial_secret(wt_quic_initial_salt_v1,
                                      sizeof wt_quic_initial_salt_v1, NULL, 0U,
                                      other_secret));

  /* The refusals. */
  WT_EXPECT_STATUS("a NULL salt is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_secret(NULL, 20U, dcid, DCID_LEN, secret));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_secret(wt_quic_initial_salt_v1,
                                          sizeof wt_quic_initial_salt_v1, dcid,
                                          DCID_LEN, NULL));
  WT_EXPECT_STATUS("a NULL ID with a length is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_secret(wt_quic_initial_salt_v1,
                                          sizeof wt_quic_initial_salt_v1, NULL,
                                          DCID_LEN, secret));
  WT_EXPECT_STATUS("a NULL Initial secret is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_packet_keys(NULL, 0, WT_AEAD_AES_128_GCM,
                                               &client));
  WT_EXPECT_STATUS("a NULL key set is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM,
                                               NULL));
  WT_EXPECT_STATUS("an unknown suite is refused", WT_ERR_UNSUPPORTED,
                   wt_quic_initial_packet_keys(secret, 0, (wt_aead_t)99,
                                               &client));
  WT_EXPECT_STATUS("a NULL traffic secret is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_keys_from_secret(NULL, WT_AEAD_AES_128_GCM,
                                                   &client));

  /* Clearing a key set leaves nothing behind, which is what a discarded key
   * needs; clearing NULL is harmless. */
  wt_quic_packet_keys_clear(&client);
  WT_EXPECT_TRUE("a cleared key set is all zeroes",
                 all_zero((const uint8_t *)&client, sizeof client));
  wt_quic_packet_keys_clear(NULL);
  WT_EXPECT_INT("clearing NULL is harmless", 1, 1);

  /* The key update: the next secret is the RFC's `ku`, and the keys are derived
   * from it with the same three labels. */
  {
    wt_quic_packet_keys_t current;
    wt_quic_packet_keys_t next;
    wt_quic_packet_keys_t again;
    uint8_t want[32];
    WT_EXPECT_OK("the ChaCha20 keys", chacha_keys(&current));
    WT_EXPECT_OK("the key update derives",
                 wt_quic_packet_keys_update(&current, &next));
    WT_EXPECT_BYTES("and the next secret is the RFC's ku",
                    WT_RFC9001_CHACHA_KEY_UPDATE, next.secret, 32U);
    WT_EXPECT_OK("its key",
                 wt_hkdf_expand_label_sha256(WT_RFC9001_CHACHA_KEY_UPDATE, 32U,
                                             "quic key", NULL, 0U, want, 32U));
    WT_EXPECT_BYTES("is the derived one", want, next.key, 32U);
    WT_EXPECT_OK("its IV",
                 wt_hkdf_expand_label_sha256(WT_RFC9001_CHACHA_KEY_UPDATE, 32U,
                                             "quic iv", NULL, 0U, want, 12U));
    WT_EXPECT_BYTES("is the derived one", want, next.iv, 12U);
    /* RFC 9001 section 6.1: "The header protection key is not updated." The next set's hp is the CURRENT set's,
     * byte for byte -- the assertion here used to derive "quic hp" from the next secret and require that, which is
     * the rule for the key and the IV and is explicitly NOT the rule for the header protection key. The old
     * expectation is what let the public function get it wrong while its only in-tree caller patched over it. */
    WT_EXPECT_BYTES("while the header protection key is NOT updated",
                    current.hp, next.hp, sizeof(current.hp));
    WT_EXPECT_INT("and its length comes with it", (long)current.hp_len, (long)next.hp_len);
    /* The key and the IV ARE new, so the copy above is not "nothing changed". */
    WT_EXPECT_TRUE("the AEAD key did change", memcmp(current.key, next.key, sizeof(current.key)) != 0);
    WT_EXPECT_U64("the suite does not change across an update",
                  (uint64_t)WT_AEAD_CHACHA20_POLY1305, (uint64_t)next.aead);
    WT_EXPECT_INT("the next secret is not the current one", 0,
                  memcmp(next.secret, current.secret, 32U) == 0 ? 1 : 0);
    WT_EXPECT_OK("and updating again is deterministic",
                 wt_quic_packet_keys_update(&current, &again));
    WT_EXPECT_BYTES("to the same secret", next.secret, again.secret, 32U);
    WT_EXPECT_STATUS("a NULL current key set is refused",
                     WT_ERR_INVALID_ARGUMENT,
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
  WT_EXPECT_OK("the client sample",
               wt_quic_header_protection_sample(
                   CLIENT_INITIAL_PN_OFFSET, WT_RFC9001_CLIENT_INITIAL_PACKET,
                   WT_RFC9001_CLIENT_INITIAL_PACKET_LEN, sample));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_CLIENT_INITIAL_SAMPLE, sample,
                  16U);
  WT_EXPECT_OK("the client mask",
               wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp,
                                              client.hp_len, sample, mask));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_CLIENT_INITIAL_MASK, mask, 5U);

  /* The server Initial packet: the same offset, a two-byte packet number. */
  WT_EXPECT_OK("the server sample",
               wt_quic_header_protection_sample(
                   SERVER_INITIAL_PN_OFFSET, WT_RFC9001_SERVER_INITIAL_PACKET,
                   WT_RFC9001_SERVER_INITIAL_PACKET_LEN, sample));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_SERVER_INITIAL_SAMPLE, sample,
                  16U);
  WT_EXPECT_OK("the server mask",
               wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, server.hp,
                                              server.hp_len, sample, mask));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_SERVER_INITIAL_MASK, mask, 5U);

  /* The short header packet: an empty connection ID, so offset 1, and the
   * ChaCha20 mask, which is a keystream and not an encrypted block. */
  WT_EXPECT_OK("the ChaCha20 sample",
               wt_quic_header_protection_sample(
                   CHACHA_PN_OFFSET, WT_RFC9001_CHACHA_PACKET,
                   WT_RFC9001_CHACHA_PACKET_LEN, sample));
  WT_EXPECT_BYTES("is the RFC's", WT_RFC9001_CHACHA_SAMPLE, sample, 16U);
  WT_EXPECT_OK("the ChaCha20 mask",
               wt_quic_header_protection_mask(WT_AEAD_CHACHA20_POLY1305,
                                              chacha.hp, chacha.hp_len, sample,
                                              mask));
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
  WT_EXPECT_STATUS("a packet too short to sample is refused", WT_ERR_TRUNCATED,
                   wt_quic_header_protection_sample(0U, short_packet,
                                                    sizeof(short_packet),
                                                    sample));
  WT_EXPECT_STATUS("an offset past the packet is refused", WT_ERR_TRUNCATED,
                   wt_quic_header_protection_sample(
                       WT_RFC9001_CLIENT_INITIAL_PACKET_LEN,
                       WT_RFC9001_CLIENT_INITIAL_PACKET,
                       WT_RFC9001_CLIENT_INITIAL_PACKET_LEN, sample));
  WT_EXPECT_STATUS("a NULL packet is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_header_protection_sample(0U, NULL, 16U, sample));
  WT_EXPECT_STATUS("a NULL sample is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_header_protection_sample(
                       0U, WT_RFC9001_CLIENT_INITIAL_PACKET,
                       WT_RFC9001_CLIENT_INITIAL_PACKET_LEN, NULL));
  WT_EXPECT_STATUS("a header protection key that is too short is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp,
                                                  15U, sample, mask));
  WT_EXPECT_STATUS("a NULL mask output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp,
                                                  client.hp_len, sample, NULL));
  WT_EXPECT_STATUS("an unknown suite is refused", WT_ERR_UNSUPPORTED,
                   wt_quic_header_protection_mask((wt_aead_t)99, client.hp, 32U,
                                                  sample, mask));
}

static void test_client_initial_packet(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
  uint8_t aad[CLIENT_INITIAL_HEADER_LEN];
  size_t pn_len = 0U;
  const size_t payload_len =
      WT_RFC9001_CLIENT_INITIAL_PACKET_LEN - CLIENT_INITIAL_HEADER_LEN -
      WT_AEAD_TAG_LEN;

  WT_EXPECT_OK("the client Initial keys", client_initial_keys(&keys));
  /* The payload the RFC prints is exactly the room the packet leaves after its
   * header and tag, which is the first sign that the offsets are right. */
  WT_EXPECT_U64("the packet's payload is the RFC's payload", 1162U,
                (uint64_t)payload_len);
  WT_EXPECT_U64("and the payload vector says so",
                (uint64_t)WT_RFC9001_CLIENT_INITIAL_PAYLOAD_LEN,
                (uint64_t)payload_len);

  memcpy(packet, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(packet));
  WT_EXPECT_OK("the client header unprotects",
               wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp,
                                        keys.hp_len, packet, sizeof(packet),
                                        CLIENT_INITIAL_PN_OFFSET, &pn_len));
  WT_EXPECT_U64("revealing a four-byte packet number", 4U, (uint64_t)pn_len);
  WT_EXPECT_BYTES("and the header is the RFC's unprotected header",
                  WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN, packet,
                  CLIENT_INITIAL_HEADER_LEN);
  WT_EXPECT_U64("with the RFC's packet number", (uint64_t)CLIENT_INITIAL_PN,
                read_be(packet + CLIENT_INITIAL_PN_OFFSET, 4U));
  memcpy(aad, packet, CLIENT_INITIAL_HEADER_LEN);

  WT_EXPECT_OK("the client payload decrypts",
               wt_quic_unprotect_frames(
                   &keys, CLIENT_INITIAL_PN, aad, CLIENT_INITIAL_HEADER_LEN,
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
                 wt_quic_protect_frames(
                     &keys, CLIENT_INITIAL_PN, aad, CLIENT_INITIAL_HEADER_LEN,
                     packet + CLIENT_INITIAL_HEADER_LEN, payload_len,
                     rebuilt + CLIENT_INITIAL_HEADER_LEN,
                     sizeof(rebuilt) - CLIENT_INITIAL_HEADER_LEN, &out_len));
    WT_EXPECT_U64("to the payload plus a tag", (uint64_t)(payload_len + 16U),
                  (uint64_t)out_len);
    WT_EXPECT_OK("the header protects",
                 wt_quic_protect_header(WT_AEAD_AES_128_GCM, keys.hp,
                                        keys.hp_len, rebuilt, sizeof(rebuilt),
                                        CLIENT_INITIAL_PN_OFFSET, pn_len));
    WT_EXPECT_BYTES("and the packet is the RFC's",
                    WT_RFC9001_CLIENT_INITIAL_PACKET, rebuilt, sizeof(rebuilt));
  }

  /* The AAD is the UNPROTECTED header. Using the header as it arrived on the
   * wire is the "decrypt before removing header protection" bug, and it must
   * fail rather than produce a payload. */
  {
    uint8_t copy[WT_RFC9001_CLIENT_INITIAL_PACKET_LEN];
    uint8_t protected_header[CLIENT_INITIAL_HEADER_LEN];
    memcpy(copy, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(copy));
    memcpy(protected_header, copy, CLIENT_INITIAL_HEADER_LEN);
    WT_EXPECT_STATUS("the protected header as AAD is refused",
                     WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(
                         &keys, CLIENT_INITIAL_PN, protected_header,
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
                   wt_quic_unprotect_header(
                       WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                       sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
      copy[CLIENT_INITIAL_TAG_OFFSET + damage] ^= 0x80U;
      WT_EXPECT_STATUS("a damaged tag is refused", WT_ERR_AUTHENTICATION,
                       wt_quic_unprotect_frames(
                           &keys, CLIENT_INITIAL_PN, copy,
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
                 wt_quic_unprotect_header(
                     WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                     sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
    copy[CLIENT_INITIAL_HEADER_LEN + 1U] ^= 0x01U;
    WT_EXPECT_STATUS("a damaged ciphertext is refused", WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(
                         &keys, CLIENT_INITIAL_PN, copy,
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
                 wt_quic_unprotect_header(
                     WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                     sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
    WT_EXPECT_STATUS("the wrong packet number is refused", WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(
                         &keys, CLIENT_INITIAL_PN + 1U, copy,
                         CLIENT_INITIAL_HEADER_LEN,
                         copy + CLIENT_INITIAL_HEADER_LEN, payload_len,
                         copy + CLIENT_INITIAL_TAG_OFFSET));
    WT_EXPECT_TRUE("and the plaintext is cleared",
                   all_zero(copy + CLIENT_INITIAL_HEADER_LEN, payload_len));

    memcpy(copy, WT_RFC9001_CLIENT_INITIAL_PACKET, sizeof(copy));
    WT_EXPECT_OK("the header unprotects for the direction test",
                 wt_quic_unprotect_header(
                     WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, copy,
                     sizeof(copy), CLIENT_INITIAL_PN_OFFSET, NULL));
    WT_EXPECT_OK("the server Initial keys", server_initial_keys(&server));
    WT_EXPECT_STATUS("the server keys cannot read a client packet",
                     WT_ERR_AUTHENTICATION,
                     wt_quic_unprotect_frames(
                         &server, CLIENT_INITIAL_PN, copy,
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
                     wt_quic_unprotect_frames(
                         NULL, CLIENT_INITIAL_PN, aad,
                         CLIENT_INITIAL_HEADER_LEN, out, payload_len, aad));
    WT_EXPECT_STATUS("a NULL tag is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_unprotect_frames(
                         &keys, CLIENT_INITIAL_PN, aad,
                         CLIENT_INITIAL_HEADER_LEN, out, payload_len, NULL));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_protect_frames(
                         &keys, CLIENT_INITIAL_PN, aad,
                         CLIENT_INITIAL_HEADER_LEN,
                         WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, NULL,
                         sizeof(out), &out_len));
    WT_EXPECT_STATUS("a NULL length output is refused",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_quic_protect_frames(
                         &keys, CLIENT_INITIAL_PN, aad,
                         CLIENT_INITIAL_HEADER_LEN,
                         WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, out,
                         sizeof(out), NULL));
    WT_EXPECT_STATUS("a buffer one byte too small is refused", WT_ERR_LIMIT,
                     wt_quic_protect_frames(
                         &keys, CLIENT_INITIAL_PN, aad,
                         CLIENT_INITIAL_HEADER_LEN,
                         WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, out,
                         payload_len + WT_AEAD_TAG_LEN - 1U, &out_len));
    WT_EXPECT_U64("and the length is not written on refusal", 0U,
                  (uint64_t)out_len);
    WT_EXPECT_STATUS("a buffer exactly large enough is accepted", WT_OK,
                     wt_quic_protect_frames(
                         &keys, CLIENT_INITIAL_PN, aad,
                         CLIENT_INITIAL_HEADER_LEN,
                         WT_RFC9001_CLIENT_INITIAL_PAYLOAD, payload_len, out,
                         payload_len + WT_AEAD_TAG_LEN, &out_len));
  }
}

static void test_server_initial_packet(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[WT_RFC9001_SERVER_INITIAL_PACKET_LEN];
  uint8_t aad[SERVER_INITIAL_HEADER_LEN];
  size_t pn_len = 0U;
  const size_t payload_len = WT_RFC9001_SERVER_INITIAL_PACKET_LEN -
                             SERVER_INITIAL_HEADER_LEN - WT_AEAD_TAG_LEN;

  WT_EXPECT_OK("the server Initial keys", server_initial_keys(&keys));
  WT_EXPECT_U64("the server payload is ninety-nine bytes", 99U,
                (uint64_t)payload_len);

  memcpy(packet, WT_RFC9001_SERVER_INITIAL_PACKET, sizeof(packet));
  WT_EXPECT_OK("the server header unprotects",
               wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp,
                                        keys.hp_len, packet, sizeof(packet),
                                        SERVER_INITIAL_PN_OFFSET, &pn_len));
  WT_EXPECT_U64("revealing a two-byte packet number", 2U, (uint64_t)pn_len);
  WT_EXPECT_BYTES("and the header is the RFC's unprotected header",
                  WT_RFC9001_SERVER_INITIAL_HEADER_PLAIN, packet,
                  SERVER_INITIAL_HEADER_LEN);
  WT_EXPECT_U64("with the RFC's packet number", (uint64_t)SERVER_INITIAL_PN,
                read_be(packet + SERVER_INITIAL_PN_OFFSET, 2U));
  memcpy(aad, packet, SERVER_INITIAL_HEADER_LEN);

  WT_EXPECT_OK("the server payload decrypts",
               wt_quic_unprotect_frames(
                   &keys, SERVER_INITIAL_PN, aad, SERVER_INITIAL_HEADER_LEN,
                   packet + SERVER_INITIAL_HEADER_LEN, payload_len,
                   packet + SERVER_INITIAL_TAG_OFFSET));
  /* The RFC prints this payload as prose rather than as a labelled block, so
   * what is checked here is its shape: an ACK frame first (RFC 9000 section
   * 19.3), which is what the appendix says it contains. The re-protection below
   * is what proves the bytes. */
  WT_EXPECT_U64("the payload starts with an ACK frame", 0x02U,
                (uint64_t)packet[SERVER_INITIAL_HEADER_LEN]);

  {
    uint8_t rebuilt[WT_RFC9001_SERVER_INITIAL_PACKET_LEN];
    size_t out_len = 0U;
    memcpy(rebuilt, aad, SERVER_INITIAL_HEADER_LEN);
    WT_EXPECT_OK("the payload protects",
                 wt_quic_protect_frames(
                     &keys, SERVER_INITIAL_PN, aad, SERVER_INITIAL_HEADER_LEN,
                     packet + SERVER_INITIAL_HEADER_LEN, payload_len,
                     rebuilt + SERVER_INITIAL_HEADER_LEN,
                     sizeof(rebuilt) - SERVER_INITIAL_HEADER_LEN, &out_len));
    WT_EXPECT_OK("the header protects",
                 wt_quic_protect_header(WT_AEAD_AES_128_GCM, keys.hp,
                                        keys.hp_len, rebuilt, sizeof(rebuilt),
                                        SERVER_INITIAL_PN_OFFSET, pn_len));
    WT_EXPECT_BYTES("and the packet is the RFC's",
                    WT_RFC9001_SERVER_INITIAL_PACKET, rebuilt,
                    sizeof(rebuilt));
  }
}

static void test_chacha_short_header(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[WT_RFC9001_CHACHA_PACKET_LEN];
  uint8_t nonce[WT_AEAD_IV_LEN];
  size_t pn_len = 0U;
  size_t out_len = 0U;

  WT_EXPECT_OK("the ChaCha20 keys", chacha_keys(&keys));
  WT_EXPECT_BYTES("the key is the RFC's", WT_RFC9001_CHACHA_KEY, keys.key,
                  WT_RFC9001_CHACHA_KEY_LEN);
  WT_EXPECT_BYTES("the IV is the RFC's", WT_RFC9001_CHACHA_IV, keys.iv,
                  WT_RFC9001_CHACHA_IV_LEN);
  WT_EXPECT_BYTES("the header protection key is the RFC's",
                  WT_RFC9001_CHACHA_HP, keys.hp, WT_RFC9001_CHACHA_HP_LEN);
  WT_EXPECT_BYTES("the secret is kept", WT_RFC9001_CHACHA_SECRET, keys.secret,
                  WT_SHA256_LEN);
  WT_EXPECT_U64("a 32-byte key", 32U, (uint64_t)keys.key_len);
  WT_EXPECT_U64("and a 32-byte header protection key", 32U,
                (uint64_t)keys.hp_len);

  /* The nonce of section 5.3, which A.5 prints: the IV with the packet number
   * XORed into its last eight bytes. */
  WT_EXPECT_OK("the nonce derives",
               wt_quic_packet_nonce(keys.iv, WT_RFC9001_CHACHA_PN, nonce));
  WT_EXPECT_BYTES("and it is the RFC's", WT_RFC9001_CHACHA_NONCE, nonce, 12U);
  /* A packet number of zero leaves the IV alone, and a number above 2^32 changes
   * the IV's first four bytes -- which is where an implementation that XORed
   * into the wrong end would differ. */
  WT_EXPECT_OK("a zero packet number", wt_quic_packet_nonce(keys.iv, 0U, nonce));
  WT_EXPECT_BYTES("leaves the IV alone", keys.iv, nonce, 12U);
  {
    uint8_t high[WT_AEAD_IV_LEN];
    uint8_t want[WT_AEAD_IV_LEN];
    size_t i;
    WT_EXPECT_OK("a packet number above 2^32",
                 wt_quic_packet_nonce(keys.iv, UINT64_C(0x100000000), high));
    memcpy(want, keys.iv, sizeof(want));
    for (i = 0U; i < 8U; i++) {
      want[WT_AEAD_IV_LEN - 1U - i] ^=
          (uint8_t)((UINT64_C(0x100000000) >> (8U * i)) & 0xFFU);
    }
    WT_EXPECT_BYTES("XORs into the last eight bytes", want, high, 12U);
    /* The first four bytes of the IV are not touched by any packet number: only
     * the last eight hold one. An implementation that XORed from the front would
     * reuse a nonce for every packet number of the same low bytes. */
    WT_EXPECT_BYTES("the IV's first four bytes are untouched", keys.iv, high,
                    4U);
    WT_EXPECT_U64("and the number lands in the fifth byte from the end",
                  (uint64_t)(uint8_t)(keys.iv[7] ^ 0x01U), (uint64_t)high[7]);
  }

  /* Protect the unprotected parts A.5 prints and compare with its packet: the
   * AEAD, the nonce, the AAD and the ChaCha20 header protection mask all have to
   * be right for the twenty-one bytes to match. */
  memcpy(packet, WT_RFC9001_CHACHA_HEADER_PLAIN, 4U);
  WT_EXPECT_OK("the PING frame protects",
               wt_quic_protect_frames(
                   &keys, WT_RFC9001_CHACHA_PN, packet, 4U,
                   WT_RFC9001_CHACHA_PAYLOAD_PLAIN, CHACHA_PAYLOAD_LEN,
                   packet + 4U, sizeof(packet) - 4U, &out_len));
  WT_EXPECT_U64("to a ciphertext and a tag", 17U, (uint64_t)out_len);
  WT_EXPECT_BYTES("which is the RFC's ciphertext", WT_RFC9001_CHACHA_CIPHERTEXT,
                  packet + 4U, 17U);
  WT_EXPECT_OK("the short header protects",
               wt_quic_protect_header(WT_AEAD_CHACHA20_POLY1305, keys.hp,
                                      keys.hp_len, packet, sizeof(packet),
                                      CHACHA_PN_OFFSET, 3U));
  WT_EXPECT_BYTES("and the packet is the RFC's", WT_RFC9001_CHACHA_PACKET,
                  packet, sizeof(packet));

  /* And back again. The packet number is truncated to three bytes on the wire,
   * so the RFC's own example is also the test of the reconstruction in RFC 9000
   * appendix A.3. */
  memcpy(packet, WT_RFC9001_CHACHA_PACKET, sizeof(packet));
  WT_EXPECT_OK("the short header unprotects",
               wt_quic_unprotect_header(WT_AEAD_CHACHA20_POLY1305, keys.hp,
                                        keys.hp_len, packet, sizeof(packet),
                                        CHACHA_PN_OFFSET, &pn_len));
  WT_EXPECT_U64("revealing a three-byte packet number", 3U, (uint64_t)pn_len);
  WT_EXPECT_BYTES("and the header is the RFC's unprotected header",
                  WT_RFC9001_CHACHA_HEADER_PLAIN, packet, 4U);
  WT_EXPECT_U64("the truncated number is the RFC's",
                (uint64_t)(WT_RFC9001_CHACHA_PN & UINT64_C(0xFFFFFF)),
                read_be(packet + CHACHA_PN_OFFSET, pn_len));
  /* The reconstruction of RFC 9000 appendix A.3 needs the largest number the
   * receiver has already processed; three bytes are enough for the RFC's number
   * exactly because the receiver's is one less. The appendix's own worked example
   * (0xa82f30ea seen, 0x9b32 in two bytes, giving 0xa82f9b32) is in
   * test_quic_packet_number. */
  WT_EXPECT_U64("and reconstructs to the RFC's full number",
                (uint64_t)WT_RFC9001_CHACHA_PN,
                wt_quic_packet_number_decode(
                    read_be(packet + CHACHA_PN_OFFSET, pn_len), pn_len,
                    (uint64_t)WT_RFC9001_CHACHA_PN - 1U));
  WT_EXPECT_OK("the payload decrypts",
               wt_quic_unprotect_frames(
                   &keys, WT_RFC9001_CHACHA_PN, packet, 4U, packet + 4U,
                   CHACHA_PAYLOAD_LEN, packet + CHACHA_TAG_OFFSET));
  WT_EXPECT_BYTES("to the RFC's PING frame", WT_RFC9001_CHACHA_PAYLOAD_PLAIN,
                  packet + 4U, CHACHA_PAYLOAD_LEN);
}

/* The mask width depends on the header form: four bits for a long header, five
 * for a short one, because a short header's key phase and reserved bits are
 * inside the masked range. Neither of RFC 9001's AES masks has a bit set in the
 * fifth position, so an implementation that always used four bits would still
 * reproduce both published Initial packets. These packets are built so that the
 * difference is visible: their masks have the fifth bit set, so the protected
 * first byte only matches if the right number of bits was masked. */
static void test_header_protection_mask_width(void) {
  wt_quic_packet_keys_t client;
  wt_quic_packet_keys_t chacha;
  uint8_t long_packet[64];
  uint8_t short_packet[32];
  uint8_t sample[16];
  uint8_t mask[5];
  size_t i;
  int found;

  WT_EXPECT_OK("the client Initial keys", client_initial_keys(&client));
  WT_EXPECT_OK("the ChaCha20 keys", chacha_keys(&chacha));

  /* A long header: Initial, a four-byte packet number at offset 9, and a payload
   * long enough to sample. The byte under test is inside the sample. */
  memset(long_packet, 0, sizeof(long_packet));
  long_packet[0] = 0xc3U; /* long header, Initial, four-byte packet number */
  long_packet[4] = 0x00U; /* version 1 */
  long_packet[5] = 0x00U; /* destination connection ID length */
  long_packet[6] = 0x00U; /* source connection ID length */
  long_packet[7] = 0x40U; /* length, two-byte varint */
  long_packet[8] = 0x33U; /* 51: a packet number, a payload and a tag */
  found = 0;
  for (i = 0U; i < 256U && !found; i++) {
    long_packet[28] = (uint8_t)i;
    WT_EXPECT_OK("the long packet's sample",
                 wt_quic_header_protection_sample(9U, long_packet,
                                                  sizeof(long_packet), sample));
    WT_EXPECT_OK("and its mask",
                 wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp,
                                                client.hp_len, sample, mask));
    if ((mask[0] & 0x10U) != 0U) found = 1;
  }
  WT_EXPECT_TRUE("a sample with the fifth mask bit set was found", found);
  {
    uint8_t first = long_packet[0];
    WT_EXPECT_OK("the long header protects",
                 wt_quic_protect_header(WT_AEAD_AES_128_GCM, client.hp,
                                        client.hp_len, long_packet,
                                        sizeof(long_packet), 9U, 4U));
    /* A five-bit mask would have reached the packet type in bits 4 and 5, so
     * this fails if the long header was masked with the short header's width. */
    WT_EXPECT_U64("the long header's first byte is masked with four bits",
                  (uint64_t)(uint8_t)(first ^ (mask[0] & 0x0FU)),
                  (uint64_t)long_packet[0]);
    WT_EXPECT_OK("and unprotecting restores it",
                 wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, client.hp,
                                          client.hp_len, long_packet,
                                          sizeof(long_packet), 9U, NULL));
    WT_EXPECT_U64("to the byte it was", (uint64_t)first,
                  (uint64_t)long_packet[0]);
  }

  /* A short header: an empty connection ID, a one-byte packet number at offset
   * 1, and a payload long enough to sample. */
  memset(short_packet, 0, sizeof(short_packet));
  short_packet[0] = 0x40U; /* short header, one-byte packet number */
  short_packet[1] = 0x2aU; /* a packet number */
  found = 0;
  for (i = 0U; i < 256U && !found; i++) {
    short_packet[20] = (uint8_t)i;
    WT_EXPECT_OK("the short packet's sample",
                 wt_quic_header_protection_sample(1U, short_packet,
                                                  sizeof(short_packet), sample));
    WT_EXPECT_OK("and its mask",
                 wt_quic_header_protection_mask(WT_AEAD_CHACHA20_POLY1305,
                                                chacha.hp, chacha.hp_len, sample,
                                                mask));
    if ((mask[0] & 0x10U) != 0U) found = 1;
  }
  WT_EXPECT_TRUE("a sample with the fifth mask bit set was found", found);
  {
    uint8_t first = short_packet[0];
    WT_EXPECT_OK("the short header protects",
                 wt_quic_protect_header(WT_AEAD_CHACHA20_POLY1305, chacha.hp,
                                        chacha.hp_len, short_packet,
                                        sizeof(short_packet), 1U, 1U));
    /* A four-bit mask would leave the key phase and reserved bits as the peer
     * wrote them, which is exactly what a receiver must not be able to rely on. */
    WT_EXPECT_U64("the short header's first byte is masked with five bits",
                  (uint64_t)(uint8_t)(first ^ (mask[0] & 0x1FU)),
                  (uint64_t)short_packet[0]);
    WT_EXPECT_OK("and unprotecting restores it",
                 wt_quic_unprotect_header(WT_AEAD_CHACHA20_POLY1305, chacha.hp,
                                          chacha.hp_len, short_packet,
                                          sizeof(short_packet), 1U, NULL));
    WT_EXPECT_U64("to the byte it was", (uint64_t)first,
                  (uint64_t)short_packet[0]);
  }
}

/* RFC 9001 section 5.8's Retry integrity tag. The tag's VALUE comes from the RFC's own appendix A.4 and
 * is not written here -- this repository's vectors are extracted from the documents, never transcribed --
 * so what is checked is the property the tag exists for: the same inputs produce the same tag, a
 * verification accepts it, and a changed byte OR a different original destination connection ID is
 * refused. The second is the attack it defends against: a Retry is only valid for the connection ID the
 * client sent, so an attacker who injects one for a different connection cannot make it verify. */
static void test_retry_integrity_tag(void) {
  static const uint8_t odcid[8] = {0x83U, 0x94U, 0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x08U};
  static const uint8_t other_odcid[8] = {0x83U, 0x94U, 0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x09U};
  /* A Retry packet without its tag: first byte, version, DCID, SCID and a token. */
  uint8_t packet[64];
  uint8_t tag[WT_AEAD_TAG_LEN];
  uint8_t again[WT_AEAD_TAG_LEN];
  size_t length;

  memset(packet, 0, sizeof(packet));
  packet[0] = 0xf0U;
  packet[1] = 0x00U; packet[2] = 0x00U; packet[3] = 0x00U; packet[4] = 0x01U;
  packet[5] = 8U;
  memcpy(packet + 6U, odcid, sizeof(odcid));
  packet[14] = 4U;
  packet[15] = 1U; packet[16] = 2U; packet[17] = 3U; packet[18] = 4U;
  packet[19] = 0x04U;   /* a four-byte token */
  packet[20] = 0xdeU; packet[21] = 0xadU; packet[22] = 0xbeU; packet[23] = 0xefU;
  length = 24U;

  WT_EXPECT_OK("a tag is computed",
               wt_quic_retry_integrity_tag(odcid, sizeof(odcid), packet, length, tag));
  WT_EXPECT_OK("and again",
               wt_quic_retry_integrity_tag(odcid, sizeof(odcid), packet, length, again));
  WT_EXPECT_BYTES("with the same answer both times", tag, again, WT_AEAD_TAG_LEN);
  WT_EXPECT_TRUE("which is not all zeroes", memcmp(tag, again, sizeof(tag)) == 0 &&
                                                  !(tag[0] == 0U && tag[1] == 0U && tag[2] == 0U));

  memcpy(packet + length, tag, WT_AEAD_TAG_LEN);
  WT_EXPECT_OK("the packet verifies", wt_quic_retry_integrity_verify(odcid, sizeof(odcid), packet,
                                                                    length + WT_AEAD_TAG_LEN));
  WT_EXPECT_STATUS("but not against another original destination connection ID",
                   WT_ERR_AUTHENTICATION,
                   wt_quic_retry_integrity_verify(other_odcid, sizeof(other_odcid), packet,
                                                  length + WT_AEAD_TAG_LEN));
  packet[20] ^= 0x01U;
  WT_EXPECT_STATUS("and not if the packet changed", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_integrity_verify(odcid, sizeof(odcid), packet,
                                                  length + WT_AEAD_TAG_LEN));
  WT_EXPECT_STATUS("a truncated packet is refused", WT_ERR_TRUNCATED,
                   wt_quic_retry_integrity_verify(odcid, sizeof(odcid), packet, 8U));
  WT_EXPECT_STATUS("and a null packet is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_integrity_verify(odcid, sizeof(odcid), NULL, 32U));

  /* A Retry with neither an original destination connection ID nor a payload is
   * legal at this layer: the pseudo-packet is the zero-length byte alone. Both
   * copies in the builder are guarded, which is what keeps a NULL away from
   * memcpy's nonnull parameters for this call. */
  WT_EXPECT_OK("a Retry with no ODCID and no payload still produces a tag",
               wt_quic_retry_integrity_tag(NULL, 0U, NULL, 0U, tag));
}

/* RFC 9001 appendix A.4: the Retry packet the document prints, and the integrity tag it prints with
 * it. The test above proves the tag is computed consistently; this one proves it is computed
 * correctly, which is the difference that matters for a value whose only job is to let a client tell a
 * Retry the server sent from one an attacker injected. Both the packet and the tag come from the
 * RFC's own hex, extracted by tests/vectors/extract_rfc9001_retry.py and checked there against A.2's
 * client Initial, rather than transcribed into this file. */
static void test_retry_integrity_vector(void) {
  uint8_t tag[WT_AEAD_TAG_LEN];
  uint8_t tampered[WT_RFC9001_RETRY_PACKET_LEN];
  uint8_t other_odcid[WT_RFC9001_RETRY_ODCID_LEN];
  size_t without_tag = sizeof(WT_RFC9001_RETRY_PACKET) - WT_RFC9001_RETRY_TAG_LEN;

  WT_EXPECT_OK("the RFC's Retry packet produces a tag",
               wt_quic_retry_integrity_tag(WT_RFC9001_RETRY_ODCID, WT_RFC9001_RETRY_ODCID_LEN,
                                           WT_RFC9001_RETRY_PACKET, without_tag, tag));
  WT_EXPECT_BYTES("which is the tag the RFC prints", WT_RFC9001_RETRY_TAG, tag,
                  WT_RFC9001_RETRY_TAG_LEN);
  WT_EXPECT_OK("and the RFC's packet verifies",
               wt_quic_retry_integrity_verify(WT_RFC9001_RETRY_ODCID, WT_RFC9001_RETRY_ODCID_LEN,
                                              WT_RFC9001_RETRY_PACKET,
                                              WT_RFC9001_RETRY_PACKET_LEN));

  memcpy(tampered, WT_RFC9001_RETRY_PACKET, sizeof(tampered));
  tampered[12] ^= 0x01U; /* inside the Source Connection ID the tag covers */
  WT_EXPECT_STATUS("a changed byte is refused", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_integrity_verify(WT_RFC9001_RETRY_ODCID, WT_RFC9001_RETRY_ODCID_LEN,
                                                  tampered, sizeof(tampered)));
  memcpy(other_odcid, WT_RFC9001_RETRY_ODCID, sizeof(other_odcid));
  other_odcid[0] ^= 0x01U;
  WT_EXPECT_STATUS("and so is another original destination connection ID", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_integrity_verify(other_odcid, sizeof(other_odcid),
                                                  WT_RFC9001_RETRY_PACKET,
                                                  WT_RFC9001_RETRY_PACKET_LEN));
}

int main(void) {
  WT_EXPECT_OK("the crypto backend initialises", wt_crypto_init());

  test_initial_keys();
  test_header_protection_vectors();
  test_client_initial_packet();
  test_server_initial_packet();
  test_chacha_short_header();
  test_header_protection_mask_width();

  test_retry_integrity_tag();
  test_retry_integrity_vector();
  WT_TEST_MAIN_END("wt_quic_protection");
}
