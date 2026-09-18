/* The Retry packet: no packet number, a token, and the integrity tag last -- its own shape, with its
 * own parser and encoder.
 *
 * This was a `main` block in `test_quic_packet.c` that the `ce1e708` split dropped. The last two
 * cases are the ones that matter: the minimum-length Retry is BUILT rather than taken as a prefix,
 * and the prefix that reaches into the tag is refused instead of underflowing the token length to
 * nearly `SIZE_MAX` (WT-203). */

#include "test_quic_packet_internal.h"

void test_a_retry_packet_round_trips(void) {
  static const uint8_t k_dcid[8] = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
  static const uint8_t k_scid[4] = {9U, 9U, 9U, 9U};
  static const uint8_t k_token[8] = {0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U, 0xA7U, 0xA8U};
  static const uint8_t k_tag[16] = {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
                                    0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U};
  uint8_t retry[64];
  wt_quic_retry_packet_t decoded;
  wt_writer_t w = wt_writer_init(retry, sizeof(retry));
  wt_cursor_t c;
  wt_quic_error_t error = 0U;

  WT_EXPECT_STATUS("a Retry encodes", WT_OK,
                   wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, k_dcid, sizeof(k_dcid),
                                               k_scid, sizeof(k_scid), k_token, sizeof(k_token),
                                               k_tag));
  WT_EXPECT_U64("to 1 + 4 + 1 + 8 + 1 + 4 + 8 + 16 bytes",
                1U + 4U + 1U + (uint64_t)sizeof(k_dcid) + 1U + (uint64_t)sizeof(k_scid) +
                    (uint64_t)sizeof(k_token) + 16U,
                (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_STATUS("and decodes", WT_OK,
                   wt_quic_retry_packet_decode(retry, wt_writer_offset(&w), &decoded, &error));
  WT_EXPECT_U64("with its token length", sizeof(k_token), (uint64_t)decoded.token_len);
  WT_EXPECT_BYTES("its token", k_token, decoded.token, sizeof(k_token));
  WT_EXPECT_BYTES("and its integrity tag", k_tag, decoded.integrity_tag, 16U);
  WT_EXPECT_U64("and its version", WT_QUIC_VERSION_1, decoded.version);
  /* A Retry shorter than a header and a tag is refused. Shortening one by the tag's length is not
   * that case: the last sixteen bytes are always the tag, so the decoder would read the token's tail
   * as one -- which is why the check is on the minimum length and not on where the tag starts. */
  WT_EXPECT_STATUS("a Retry below the minimum length is truncated", WT_ERR_TRUNCATED,
                   wt_quic_retry_packet_decode(retry, 20U, &decoded, &error));
  /* A Retry of exactly the minimum: ZERO-length connection IDs and a three-byte token, which is 27
   * bytes.
   *
   * The first version of this case decoded a 27-byte PREFIX of the packet built above, whose header
   * names an 8-byte destination and a 4-byte source ID -- so the "minimum" it claimed to test was
   * really a header that ran past the tag, and it passed only because the token length UNDERFLOWED
   * to nearly `SIZE_MAX`. An audit found the underflow and this case with it: a test that passes for
   * the wrong reason is the thing that hides the defect beside it. So the minimum is now BUILT, the
   * prefix is asserted to be REFUSED, and the underflow has the regression test it did not have. */
  {
    static const uint8_t k_short_token[3] = {0xA1U, 0xA2U, 0xA3U};
    static const uint8_t k_short_scid[1] = {0x77U};
    uint8_t minimal[64];
    wt_writer_t minimal_writer = wt_writer_init(minimal, sizeof(minimal));
    wt_quic_retry_packet_t minimal_decoded;

    /* The shortest Retry that can exist: no destination connection ID, the one-byte source ID a
     * server that retries must have chosen (RFC 9000 section 17.2.5), and a three-byte token. */
    WT_EXPECT_STATUS("a Retry with the shortest header encodes", WT_OK,
                     wt_quic_retry_packet_encode(&minimal_writer, WT_QUIC_VERSION_1, NULL, 0U,
                                                 k_short_scid, sizeof(k_short_scid), k_short_token,
                                                 sizeof(k_short_token), k_tag));
    WT_EXPECT_U64("to exactly the minimum length",
                  (uint64_t)(1U + 4U + 1U + 0U + 1U + 1U + 3U + 16U),
                  (uint64_t)wt_writer_offset(&minimal_writer));
    WT_EXPECT_STATUS("and that minimum parses", WT_OK,
                     wt_quic_retry_packet_decode(minimal, wt_writer_offset(&minimal_writer),
                                                 &minimal_decoded, &error));
    WT_EXPECT_U64("with its short token", (uint64_t)sizeof(k_short_token),
                  (uint64_t)minimal_decoded.token_len);
    WT_EXPECT_BYTES("byte for byte", k_short_token, minimal_decoded.token, sizeof(k_short_token));
    WT_EXPECT_BYTES("and its tag", k_tag, minimal_decoded.integrity_tag, 16U);

    /* A header that reaches into the tag is TRUNCATED, not a token of nearly `SIZE_MAX` bytes: this
     * is the exact packet the audit used, and before the guard it returned WT_OK with a token view
     * past the end. */
    WT_EXPECT_STATUS("a header that runs into the tag is truncated", WT_ERR_TRUNCATED,
                     wt_quic_retry_packet_decode(retry, 26U, &decoded, &error));
  }
  /* The long header parser refuses a Retry, which has its own shape. */
  c = wt_cursor_init(retry, wt_writer_offset(&w));
  {
    wt_quic_long_header_t long_header;
    WT_EXPECT_STATUS("the long header parser refuses a Retry", WT_ERR_PROTOCOL,
                     wt_quic_long_header_decode(&c, &long_header, &error));
    WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);
  }
}
