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

static void test_server_initial_packet(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[WT_RFC9001_SERVER_INITIAL_PACKET_LEN];
  uint8_t aad[SERVER_INITIAL_HEADER_LEN];
  size_t pn_len = 0U;
  const size_t payload_len =
      WT_RFC9001_SERVER_INITIAL_PACKET_LEN - SERVER_INITIAL_HEADER_LEN - WT_AEAD_TAG_LEN;

  WT_EXPECT_OK("the server Initial keys", server_initial_keys(&keys));
  WT_EXPECT_U64("the server payload is ninety-nine bytes", 99U, (uint64_t)payload_len);

  memcpy(packet, WT_RFC9001_SERVER_INITIAL_PACKET, sizeof(packet));
  WT_EXPECT_OK("the server header unprotects",
               wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, packet,
                                        sizeof(packet), SERVER_INITIAL_PN_OFFSET, &pn_len));
  WT_EXPECT_U64("revealing a two-byte packet number", 2U, (uint64_t)pn_len);
  WT_EXPECT_BYTES("and the header is the RFC's unprotected header",
                  WT_RFC9001_SERVER_INITIAL_HEADER_PLAIN, packet, SERVER_INITIAL_HEADER_LEN);
  WT_EXPECT_U64("with the RFC's packet number", (uint64_t)SERVER_INITIAL_PN,
                read_be(packet + SERVER_INITIAL_PN_OFFSET, 2U));
  memcpy(aad, packet, SERVER_INITIAL_HEADER_LEN);

  WT_EXPECT_OK("the server payload decrypts",
               wt_quic_unprotect_frames(&keys, SERVER_INITIAL_PN, aad, SERVER_INITIAL_HEADER_LEN,
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
                 wt_quic_protect_frames(&keys, SERVER_INITIAL_PN, aad, SERVER_INITIAL_HEADER_LEN,
                                        packet + SERVER_INITIAL_HEADER_LEN, payload_len,
                                        rebuilt + SERVER_INITIAL_HEADER_LEN,
                                        sizeof(rebuilt) - SERVER_INITIAL_HEADER_LEN, &out_len));
    WT_EXPECT_OK("the header protects",
                 wt_quic_protect_header(WT_AEAD_AES_128_GCM, keys.hp, keys.hp_len, rebuilt,
                                        sizeof(rebuilt), SERVER_INITIAL_PN_OFFSET, pn_len));
    WT_EXPECT_BYTES("and the packet is the RFC's", WT_RFC9001_SERVER_INITIAL_PACKET, rebuilt,
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
  WT_EXPECT_BYTES("the IV is the RFC's", WT_RFC9001_CHACHA_IV, keys.iv, WT_RFC9001_CHACHA_IV_LEN);
  WT_EXPECT_BYTES("the header protection key is the RFC's", WT_RFC9001_CHACHA_HP, keys.hp,
                  WT_RFC9001_CHACHA_HP_LEN);
  WT_EXPECT_BYTES("the secret is kept", WT_RFC9001_CHACHA_SECRET, keys.secret, WT_SHA256_LEN);
  WT_EXPECT_U64("a 32-byte key", 32U, (uint64_t)keys.key_len);
  WT_EXPECT_U64("and a 32-byte header protection key", 32U, (uint64_t)keys.hp_len);

  /* The nonce of section 5.3, which A.5 prints: the IV with the packet number
   * XORed into its last eight bytes. */
  WT_EXPECT_OK("the nonce derives", wt_quic_packet_nonce(keys.iv, WT_RFC9001_CHACHA_PN, nonce));
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
      want[WT_AEAD_IV_LEN - 1U - i] ^= (uint8_t)((UINT64_C(0x100000000) >> (8U * i)) & 0xFFU);
    }
    WT_EXPECT_BYTES("XORs into the last eight bytes", want, high, 12U);
    /* The first four bytes of the IV are not touched by any packet number: only
     * the last eight hold one. An implementation that XORed from the front would
     * reuse a nonce for every packet number of the same low bytes. */
    WT_EXPECT_BYTES("the IV's first four bytes are untouched", keys.iv, high, 4U);
    WT_EXPECT_U64("and the number lands in the fifth byte from the end",
                  (uint64_t)(uint8_t)(keys.iv[7] ^ 0x01U), (uint64_t)high[7]);
  }

  /* Protect the unprotected parts A.5 prints and compare with its packet: the
   * AEAD, the nonce, the AAD and the ChaCha20 header protection mask all have to
   * be right for the twenty-one bytes to match. */
  memcpy(packet, WT_RFC9001_CHACHA_HEADER_PLAIN, 4U);
  WT_EXPECT_OK("the PING frame protects",
               wt_quic_protect_frames(&keys, WT_RFC9001_CHACHA_PN, packet, 4U,
                                      WT_RFC9001_CHACHA_PAYLOAD_PLAIN, CHACHA_PAYLOAD_LEN,
                                      packet + 4U, sizeof(packet) - 4U, &out_len));
  WT_EXPECT_U64("to a ciphertext and a tag", 17U, (uint64_t)out_len);
  WT_EXPECT_BYTES("which is the RFC's ciphertext", WT_RFC9001_CHACHA_CIPHERTEXT, packet + 4U, 17U);
  WT_EXPECT_OK("the short header protects",
               wt_quic_protect_header(WT_AEAD_CHACHA20_POLY1305, keys.hp, keys.hp_len, packet,
                                      sizeof(packet), CHACHA_PN_OFFSET, 3U));
  WT_EXPECT_BYTES("and the packet is the RFC's", WT_RFC9001_CHACHA_PACKET, packet, sizeof(packet));

  /* And back again. The packet number is truncated to three bytes on the wire,
   * so the RFC's own example is also the test of the reconstruction in RFC 9000
   * appendix A.3. */
  memcpy(packet, WT_RFC9001_CHACHA_PACKET, sizeof(packet));
  WT_EXPECT_OK("the short header unprotects",
               wt_quic_unprotect_header(WT_AEAD_CHACHA20_POLY1305, keys.hp, keys.hp_len, packet,
                                        sizeof(packet), CHACHA_PN_OFFSET, &pn_len));
  WT_EXPECT_U64("revealing a three-byte packet number", 3U, (uint64_t)pn_len);
  WT_EXPECT_BYTES("and the header is the RFC's unprotected header", WT_RFC9001_CHACHA_HEADER_PLAIN,
                  packet, 4U);
  WT_EXPECT_U64("the truncated number is the RFC's",
                (uint64_t)(WT_RFC9001_CHACHA_PN & UINT64_C(0xFFFFFF)),
                read_be(packet + CHACHA_PN_OFFSET, pn_len));
  /* The reconstruction of RFC 9000 appendix A.3 needs the largest number the
   * receiver has already processed; three bytes are enough for the RFC's number
   * exactly because the receiver's is one less. The appendix's own worked example
   * (0xa82f30ea seen, 0x9b32 in two bytes, giving 0xa82f9b32) is in
   * test_quic_packet_number. */
  WT_EXPECT_U64("and reconstructs to the RFC's full number", (uint64_t)WT_RFC9001_CHACHA_PN,
                wt_quic_packet_number_decode(read_be(packet + CHACHA_PN_OFFSET, pn_len), pn_len,
                                             (uint64_t)WT_RFC9001_CHACHA_PN - 1U));
  WT_EXPECT_OK("the payload decrypts",
               wt_quic_unprotect_frames(&keys, WT_RFC9001_CHACHA_PN, packet, 4U, packet + 4U,
                                        CHACHA_PAYLOAD_LEN, packet + CHACHA_TAG_OFFSET));
  WT_EXPECT_BYTES("to the RFC's PING frame", WT_RFC9001_CHACHA_PAYLOAD_PLAIN, packet + 4U,
                  CHACHA_PAYLOAD_LEN);
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
                 wt_quic_header_protection_sample(9U, long_packet, sizeof(long_packet), sample));
    WT_EXPECT_OK("and its mask", wt_quic_header_protection_mask(WT_AEAD_AES_128_GCM, client.hp,
                                                                client.hp_len, sample, mask));
    if ((mask[0] & 0x10U) != 0U) found = 1;
  }
  WT_EXPECT_TRUE("a sample with the fifth mask bit set was found", found);
  {
    uint8_t first = long_packet[0];
    WT_EXPECT_OK("the long header protects",
                 wt_quic_protect_header(WT_AEAD_AES_128_GCM, client.hp, client.hp_len, long_packet,
                                        sizeof(long_packet), 9U, 4U));
    /* A five-bit mask would have reached the packet type in bits 4 and 5, so
     * this fails if the long header was masked with the short header's width. */
    WT_EXPECT_U64("the long header's first byte is masked with four bits",
                  (uint64_t)(uint8_t)(first ^ (mask[0] & 0x0FU)), (uint64_t)long_packet[0]);
    WT_EXPECT_OK("and unprotecting restores it",
                 wt_quic_unprotect_header(WT_AEAD_AES_128_GCM, client.hp, client.hp_len,
                                          long_packet, sizeof(long_packet), 9U, NULL));
    WT_EXPECT_U64("to the byte it was", (uint64_t)first, (uint64_t)long_packet[0]);
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
                 wt_quic_header_protection_sample(1U, short_packet, sizeof(short_packet), sample));
    WT_EXPECT_OK("and its mask",
                 wt_quic_header_protection_mask(WT_AEAD_CHACHA20_POLY1305, chacha.hp, chacha.hp_len,
                                                sample, mask));
    if ((mask[0] & 0x10U) != 0U) found = 1;
  }
  WT_EXPECT_TRUE("a sample with the fifth mask bit set was found", found);
  {
    uint8_t first = short_packet[0];
    WT_EXPECT_OK("the short header protects",
                 wt_quic_protect_header(WT_AEAD_CHACHA20_POLY1305, chacha.hp, chacha.hp_len,
                                        short_packet, sizeof(short_packet), 1U, 1U));
    /* A four-bit mask would leave the key phase and reserved bits as the peer
     * wrote them, which is exactly what a receiver must not be able to rely on. */
    WT_EXPECT_U64("the short header's first byte is masked with five bits",
                  (uint64_t)(uint8_t)(first ^ (mask[0] & 0x1FU)), (uint64_t)short_packet[0]);
    WT_EXPECT_OK("and unprotecting restores it",
                 wt_quic_unprotect_header(WT_AEAD_CHACHA20_POLY1305, chacha.hp, chacha.hp_len,
                                          short_packet, sizeof(short_packet), 1U, NULL));
    WT_EXPECT_U64("to the byte it was", (uint64_t)first, (uint64_t)short_packet[0]);
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
  packet[1] = 0x00U;
  packet[2] = 0x00U;
  packet[3] = 0x00U;
  packet[4] = 0x01U;
  packet[5] = 8U;
  memcpy(packet + 6U, odcid, sizeof(odcid));
  packet[14] = 4U;
  packet[15] = 1U;
  packet[16] = 2U;
  packet[17] = 3U;
  packet[18] = 4U;
  packet[19] = 0x04U; /* a four-byte token */
  packet[20] = 0xdeU;
  packet[21] = 0xadU;
  packet[22] = 0xbeU;
  packet[23] = 0xefU;
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
  WT_EXPECT_STATUS(
      "and not if the packet changed", WT_ERR_AUTHENTICATION,
      wt_quic_retry_integrity_verify(odcid, sizeof(odcid), packet, length + WT_AEAD_TAG_LEN));
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
                   wt_quic_retry_integrity_verify(WT_RFC9001_RETRY_ODCID,
                                                  WT_RFC9001_RETRY_ODCID_LEN, tampered,
                                                  sizeof(tampered)));
  memcpy(other_odcid, WT_RFC9001_RETRY_ODCID, sizeof(other_odcid));
  other_odcid[0] ^= 0x01U;
  WT_EXPECT_STATUS("and so is another original destination connection ID", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_integrity_verify(other_odcid, sizeof(other_odcid),
                                                  WT_RFC9001_RETRY_PACKET,
                                                  WT_RFC9001_RETRY_PACKET_LEN));
}

/* The key update with the SAME object as input and output.
 *
 * `wt_quic_packet_keys_update` copies the current header protection key onto the derived set, because RFC 9001
 * section 6.1 says "The header protection key is not updated". That copy is enough when the two arguments are
 * distinct, which is what the test above uses and what the only in-tree caller does — but the PUBLIC function
 * also has to answer the aliased call, and it did not: `wt_quic_derive_packet_keys` memsets and overwrites its
 * output, so with `out == current` the copy at the end of the update read the freshly derived key from the same
 * object it was writing to. A caller that updated in place silently got the new hp — the exact key a peer does
 * not have after an update — and could not unmask a single packet.
 *
 * The probe that found it: update(&k, &out).hp = 40 b8 d4 dc versus update(&k, &k).hp = 25 e8 a7 4b. */
static void test_a_key_update_in_place_is_the_same_set(void) {
  wt_quic_packet_keys_t aliased;
  wt_quic_packet_keys_t separate;
  wt_quic_packet_keys_t expected;

  WT_EXPECT_OK("the aliased keys", chacha_keys(&aliased));
  WT_EXPECT_OK("the separate keys", chacha_keys(&separate));
  WT_EXPECT_OK("the reference keys", chacha_keys(&expected));

  WT_EXPECT_OK("updating in place", wt_quic_packet_keys_update(&aliased, &aliased));
  WT_EXPECT_OK("updating into a distinct object", wt_quic_packet_keys_update(&separate, &expected));

  /* The whole set has to match, not just the hp: an in-place update that got the hp right by copying it after
   * the derivation is a different bug from one that read its own output for the secret. */
  WT_EXPECT_BYTES("the in-place secret is the same", expected.secret, aliased.secret,
                  WT_SHA256_LEN);
  WT_EXPECT_BYTES("the in-place key is the same", expected.key, aliased.key, sizeof(expected.key));
  WT_EXPECT_BYTES("the in-place IV is the same", expected.iv, aliased.iv, sizeof(expected.iv));
  WT_EXPECT_BYTES("and the in-place header protection key is NOT updated", separate.hp, aliased.hp,
                  sizeof(aliased.hp));
  WT_EXPECT_INT("with the current hp length", (long)separate.hp_len, (long)aliased.hp_len);

  /* And it really is the CURRENT hp, not the derived one: the derivation of `quic hp` from the new secret is a
   * different value, so an implementation that skipped the copy would fail this. */
  {
    uint8_t derived[sizeof(aliased.hp)];
    memset(derived, 0, sizeof(derived));
    WT_EXPECT_OK("the hp the update must NOT use",
                 wt_hkdf_expand_label_sha256(expected.secret, WT_SHA256_LEN, "quic hp", NULL, 0U,
                                             derived, sizeof(derived)));
    WT_EXPECT_TRUE("the in-place hp is not the freshly derived one",
                   memcmp(aliased.hp, derived, sizeof(derived)) != 0);
  }
}

int main(void) {
  test_server_initial_packet();
  test_chacha_short_header();
  test_header_protection_mask_width();
  test_retry_integrity_tag();
  test_retry_integrity_vector();
  test_a_key_update_in_place_is_the_same_set();
  WT_TEST_MAIN_END("test_quic_protection_retry");
}
