/* Retry tokens: the opaque, integrity-protected value a server hands a client (WT-168, RFC 9000 section 8.1.4).
 *
 * The property that matters is not that a token ROUND TRIPS -- that is the easy half -- but that a token this
 * server did not write, or wrote for another peer, or wrote too long ago, does not validate. Each of those is a
 * separate case below, because the failure they share (a client that gets a connection for an address it does not
 * own, or an attacker that does) is the whole reason the tag exists.
 *
 * The address form is checked too: two peers whose addresses differ must produce tokens that do not validate for
 * each other, which is the property that makes a token a proof of reachability rather than a session cookie.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/retry_token.h"
#include "webtransport/runtime/udp.h"

static const uint8_t k_secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xaaU,
    0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU, 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xabU,
    0xcdU, 0xefU, 0xfeU, 0xdcU, 0xbaU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U};

static void fill(uint8_t *out, size_t length, uint8_t seed) {
  size_t i;
  for (i = 0U; i < length; i++)
    out[i] = (uint8_t)(seed + i);
}

/* A peer's address in the canonical byte form the token hashes. */
static size_t encode_address(wt_udp_family_t family, uint16_t port, uint8_t last_byte, uint8_t *out,
                             size_t capacity) {
  wt_udp_address_t address;

  memset(&address, 0, sizeof(address));
  address.family = family;
  address.port = port;
  address.bytes[15] = last_byte;
  if (family == WT_UDP_IPV4) address.bytes[3] = last_byte;
  return wt_udp_address_encode(&address, out, capacity);
}

int main(void) {
  uint8_t address[WT_UDP_ADDRESS_ENCODED_LENGTH];
  uint8_t other_address[WT_UDP_ADDRESS_ENCODED_LENGTH];
  uint8_t original[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  uint8_t odcid[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  uint8_t token[WT_QUIC_RETRY_TOKEN_MAX];
  uint8_t tampered[WT_QUIC_RETRY_TOKEN_MAX];
  uint8_t other_secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN];
  size_t address_length;
  size_t other_address_length;
  size_t token_length = 0U;
  size_t odcid_length = 0U;
  const uint64_t k_now = 7000000U;

  address_length = encode_address(WT_UDP_IPV6, 4433U, 0x2aU, address, sizeof(address));
  other_address_length =
      encode_address(WT_UDP_IPV6, 4434U, 0x2aU, other_address, sizeof(other_address));
  WT_EXPECT_U64("the canonical address form is one length", WT_UDP_ADDRESS_ENCODED_LENGTH,
                (uint64_t)address_length);
  WT_EXPECT_U64("and the same length for the other peer", WT_UDP_ADDRESS_ENCODED_LENGTH,
                (uint64_t)other_address_length);
  WT_EXPECT_INT("two peers encode differently", 0,
                memcmp(address, other_address, address_length) == 0);
  WT_EXPECT_U64("a buffer too small encodes nothing", 0U,
                (uint64_t)encode_address(WT_UDP_IPV4, 1U, 1U, other_address, 4U));

  fill(original, sizeof(original), 0x40U);

  /* The round trip, and what it hands back. */
  WT_EXPECT_OK("a token builds",
               wt_quic_retry_token_build(k_secret, address, address_length, original, 8U, k_now,
                                         token, sizeof(token), &token_length));
  WT_EXPECT_TRUE("with bytes in it", token_length > WT_QUIC_RETRY_TOKEN_TAG_LEN);
  WT_EXPECT_OK("and validates for the same peer and secret",
               wt_quic_retry_token_validate(k_secret, address, address_length, k_now, 1000U, token,
                                            token_length, odcid, sizeof(odcid), &odcid_length));
  WT_EXPECT_U64("returning the original destination connection ID", 8U, (uint64_t)odcid_length);
  WT_EXPECT_BYTES("byte for byte", original, odcid, 8U);

  /* A different original destination ID, and a full-length one, are both carried. */
  WT_EXPECT_OK("a twenty-byte original builds",
               wt_quic_retry_token_build(k_secret, address, address_length, original,
                                         WT_QUIC_MAX_CONNECTION_ID_LENGTH, k_now, token,
                                         sizeof(token), &token_length));
  WT_EXPECT_OK("and validates",
               wt_quic_retry_token_validate(k_secret, address, address_length, k_now, 0U, token,
                                            token_length, odcid, sizeof(odcid), &odcid_length));
  WT_EXPECT_U64("with all twenty bytes", (uint64_t)WT_QUIC_MAX_CONNECTION_ID_LENGTH,
                (uint64_t)odcid_length);

  /* The peer. A token issued for the address the client came FROM must not work from anywhere else, or a client
   * could hand it to an accomplice. */
  WT_EXPECT_STATUS("a token for another address does not validate", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_token_validate(k_secret, other_address, other_address_length,
                                                k_now, 0U, token, token_length, odcid,
                                                sizeof(odcid), &odcid_length));
  WT_EXPECT_STATUS("nor for a truncated address", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_token_validate(k_secret, address, 0U, k_now, 0U, token,
                                                token_length, odcid, sizeof(odcid), &odcid_length));

  /* The secret: a token signed by anyone else is not this server's. */
  fill(other_secret, sizeof(other_secret), 0x80U);
  WT_EXPECT_STATUS("a token from another server does not validate", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_token_validate(other_secret, address, address_length, k_now, 0U,
                                                token, token_length, odcid, sizeof(odcid),
                                                &odcid_length));

  /* Tampering. Every byte that carries meaning is covered by the tag: the format byte, the timestamp, the
   * address, the length, the original destination ID and the tag itself. */
  {
    size_t i;
    /* The last byte of the original destination ID (just before the tag), the timestamp, the address, the length
     * byte, the format byte, and a tag byte. */
    static const size_t k_tamper_offsets[] = {42U + 19U, 1U, 9U, 41U, 0U, 62U};
    for (i = 0U; i < sizeof(k_tamper_offsets) / sizeof(k_tamper_offsets[0]); i++) {
      memcpy(tampered, token, token_length);
      tampered[k_tamper_offsets[i]] ^= 0x01U;
      WT_EXPECT_STATUS("a tampered byte is not this server's token", WT_ERR_AUTHENTICATION,
                       wt_quic_retry_token_validate(k_secret, address, address_length, k_now, 0U,
                                                    tampered, token_length, odcid, sizeof(odcid),
                                                    &odcid_length));
    }
  }

  /* Lengths a token cannot have. These are the TOKEN's fault rather than the caller's -- the caller passes the
   * length it received -- so they are AUTHENTICATION like every other "not this server's token" answer. */
  WT_EXPECT_STATUS("a token shorter than the layout is not ours", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_token_validate(k_secret, address, address_length, k_now, 0U, token,
                                                8U, odcid, sizeof(odcid), &odcid_length));
  WT_EXPECT_STATUS("and neither is one longer than it", WT_ERR_AUTHENTICATION,
                   wt_quic_retry_token_validate(k_secret, address, address_length, k_now, 0U, token,
                                                sizeof(token) + 1U, odcid, sizeof(odcid),
                                                &odcid_length));
  /* And a caller's own mistake is told apart from an attack. */
  WT_EXPECT_STATUS("a null token is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_token_validate(k_secret, address, address_length, k_now, 0U, NULL,
                                                0U, odcid, sizeof(odcid), &odcid_length));
  WT_EXPECT_STATUS("and so is an output buffer that cannot hold the ID", WT_ERR_LIMIT,
                   wt_quic_retry_token_validate(k_secret, address, address_length, k_now, 0U, token,
                                                token_length, odcid, 4U, &odcid_length));

  /* Expiry. A token is a proof of a round trip that happened, not a permanent credential. */
  WT_EXPECT_STATUS("a token inside the maximum age validates", WT_OK,
                   wt_quic_retry_token_validate(k_secret, address, address_length, k_now + 1000U,
                                                1000U, token, token_length, odcid, sizeof(odcid),
                                                &odcid_length));
  WT_EXPECT_STATUS("one older than it does not", WT_ERR_STATE,
                   wt_quic_retry_token_validate(k_secret, address, address_length, k_now + 1001U,
                                                1000U, token, token_length, odcid, sizeof(odcid),
                                                &odcid_length));
  WT_EXPECT_STATUS("and a token from the future is not spent on either", WT_ERR_STATE,
                   wt_quic_retry_token_validate(k_secret, address, address_length, k_now - 1U,
                                                1000U, token, token_length, odcid, sizeof(odcid),
                                                &odcid_length));
  WT_EXPECT_STATUS("no bound means no expiry check", WT_OK,
                   wt_quic_retry_token_validate(k_secret, address, address_length,
                                                k_now + 1000000000U, 0U, token, token_length, odcid,
                                                sizeof(odcid), &odcid_length));

  /* The builder's own bounds, each refused rather than truncated. */
  WT_EXPECT_STATUS("a capacity that cannot hold the token is refused", WT_ERR_LIMIT,
                   wt_quic_retry_token_build(k_secret, address, address_length, original, 8U, k_now,
                                             token, 16U, &token_length));
  WT_EXPECT_STATUS("no original destination ID is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_token_build(k_secret, address, address_length, original, 0U, k_now,
                                             token, sizeof(token), &token_length));
  WT_EXPECT_STATUS("and one longer than a connection ID", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_token_build(k_secret, address, address_length, original, 21U,
                                             k_now, token, sizeof(token), &token_length));
  WT_EXPECT_STATUS("an address longer than the form allows", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_token_build(k_secret, address,
                                             WT_QUIC_RETRY_TOKEN_ADDRESS_MAX + 1U, original, 8U,
                                             k_now, token, sizeof(token), &token_length));
  WT_EXPECT_STATUS("a null secret", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_token_build(NULL, address, address_length, original, 8U, k_now,
                                             token, sizeof(token), &token_length));

  WT_TEST_MAIN_END("wt_quic_retry_token");
}
