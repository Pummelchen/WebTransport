/* Shared by the two halves of test_quic_protection.c after the split.
 * Composed in the order it has to be read: guard, includes, body defines, shared helpers.
 * The defines come before the helpers because the helpers use them, and `static inline`
 * because a file-static helper cannot cross a translation unit. */
#ifndef TEST_QUIC_PROTECTION_RETRY_SUPPORT_H
#define TEST_QUIC_PROTECTION_RETRY_SUPPORT_H

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

#define CLIENT_INITIAL_HEADER_LEN 22U
#define SERVER_INITIAL_HEADER_LEN 20U
#define CLIENT_INITIAL_PN_OFFSET 18U
#define SERVER_INITIAL_PN_OFFSET 18U
#define CHACHA_PN_OFFSET 1U
#define CLIENT_INITIAL_PN 2U
#define SERVER_INITIAL_PN 1U
#define CLIENT_INITIAL_TAG_OFFSET (WT_RFC9001_CLIENT_INITIAL_PACKET_LEN - WT_AEAD_TAG_LEN)
#define SERVER_INITIAL_TAG_OFFSET (WT_RFC9001_SERVER_INITIAL_PACKET_LEN - WT_AEAD_TAG_LEN)
#define CHACHA_TAG_OFFSET (WT_RFC9001_CHACHA_PACKET_LEN - WT_AEAD_TAG_LEN)
#define CHACHA_PAYLOAD_LEN 1U
#define DCID_OFFSET 6U
#define DCID_LEN 8U

static inline uint64_t read_be(const uint8_t *bytes, size_t len) {
  uint64_t value = 0U;
  size_t i;
  for (i = 0U; i < len; i++) {
    value = (value << 8) | (uint64_t)bytes[i];
  }
  return value;
}

static inline int all_zero(const uint8_t *bytes, size_t len) {
  size_t i;
  for (i = 0U; i < len; i++) {
    if (bytes[i] != 0U) return 0;
  }
  return 1;
}

static inline wt_status_t client_initial_keys(wt_quic_packet_keys_t *out) {
  uint8_t secret[WT_SHA256_LEN];
  wt_status_t status = wt_quic_initial_secret(
      wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1,
      WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN + DCID_OFFSET, DCID_LEN, secret);
  if (status != WT_OK) return status;
  return wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM, out);
}

static inline wt_status_t server_initial_keys(wt_quic_packet_keys_t *out) {
  uint8_t secret[WT_SHA256_LEN];
  wt_status_t status = wt_quic_initial_secret(
      wt_quic_initial_salt_v1, sizeof wt_quic_initial_salt_v1,
      WT_RFC9001_CLIENT_INITIAL_HEADER_PLAIN + DCID_OFFSET, DCID_LEN, secret);
  if (status != WT_OK) return status;
  return wt_quic_initial_packet_keys(secret, 1, WT_AEAD_AES_128_GCM, out);
}

static inline wt_status_t chacha_keys(wt_quic_packet_keys_t *out) {
  return wt_quic_packet_keys_from_secret(WT_RFC9001_CHACHA_SECRET, WT_AEAD_CHACHA20_POLY1305, out);
}

#endif
