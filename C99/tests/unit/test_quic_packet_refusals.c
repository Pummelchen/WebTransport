/* What the packet decoders and encoders must refuse: the fixed bit, a connection ID above twenty
 * bytes, truncation at every field boundary, and the argument checks the encoders state.
 *
 * These are the `main` blocks the `ce1e708` split dropped from `test_quic_packet.c`. The reserved
 * bits are the one case the old text needed re-reading: the audit made the decoder REPORT them
 * rather than refuse for them (WT-167), so the assertion is about what the decoder says now --
 * reported on the way to the refusal the Length field still earns, and accepted when the rest of
 * the header is well-formed. */

#include "test_quic_packet_internal.h"

void test_the_long_header_refusals(void) {
  /* The fixed bit cleared: RFC 9000 section 17.2 says such a packet is not valid in this version and
   * must be discarded. */
  static const uint8_t k_no_fixed[32] = {0x80U, 0x00U, 0x00U, 0x00U, 0x01U};
  static const uint8_t k_short_no_fixed[16] = {0x00U, 1U, 2U, 3U, 4U};
  static const uint8_t k_reserved[32] = {0xccU, 0x00U, 0x00U, 0x00U, 0x01U};
  static const uint8_t k_bad_cid[32] = {0xc0U, 0x00U, 0x00U, 0x00U, 0x01U, 0x15U};
  wt_quic_long_header_t long_header;
  wt_quic_short_header_t short_header;
  wt_cursor_t c;
  wt_quic_error_t error = 0U;

  c = wt_cursor_init(k_no_fixed, sizeof(k_no_fixed));
  WT_EXPECT_STATUS("a long header without the fixed bit is refused", WT_ERR_PROTOCOL,
                   wt_quic_long_header_decode(&c, &long_header, &error));
  WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);

  c = wt_cursor_init(k_short_no_fixed, sizeof(k_short_no_fixed));
  WT_EXPECT_STATUS("a short header without the fixed bit is refused", WT_ERR_PROTOCOL,
                   wt_quic_short_header_decode(&c, 8U, &short_header, &error));

  /* Reserved bits are REPORTED, not refused (WT-167). RFC 9000 section 17.2 makes them a violation
   * "after removing both packet and header protection", and they are inside the AEAD's associated
   * data -- so a value that is non-zero after header unprotection may be a packet protected with
   * another key set, which RFC 9001 section 5.3 says to DISCARD. The decoder reports;
   * `wt_quic_packet_read` refuses once the packet has authenticated, which is what
   * `test_quic_packet_io` asserts. Refusing here turned every packet from another key epoch into a
   * violation against the peer, which is what a Retry produced against quiche. */
  error = 0U;
  c = wt_cursor_init(k_reserved, sizeof(k_reserved));
  WT_EXPECT_STATUS("a long header with reserved bits set is not refused FOR them", WT_ERR_PROTOCOL,
                   wt_quic_long_header_decode(&c, &long_header, &error));
  WT_EXPECT_U64("  but for the Length field this buffer also gets wrong",
                WT_QUIC_FRAME_ENCODING_ERROR, error);
  WT_EXPECT_INT("with the reserved bits reported on the way", 1, long_header.reserved_bits_set);

  /* And a WELL-FORMED header whose reserved bits are set parses, reporting them: the violation is
   * the caller's to make once the packet has authenticated (WT-167). */
  {
    static const uint8_t k_reserved_ok[17] = {
        0xccU, 0x00U, 0x00U, 0x00U, 0x01U, /* Initial, one-byte packet number, reserved bits set */
        0x00U,                             /* a zero-length Destination Connection ID */
        0x00U,                             /* and a zero-length Source Connection ID */
        0x00U,                             /* no token */
        0x08U,                             /* Length: one packet number byte and seven of payload */
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
    error = 0U;
    c = wt_cursor_init(k_reserved_ok, sizeof(k_reserved_ok));
    WT_EXPECT_STATUS("a well-formed header with reserved bits set parses", WT_OK,
                     wt_quic_long_header_decode(&c, &long_header, &error));
    WT_EXPECT_INT("reporting them", 1, long_header.reserved_bits_set);
    WT_EXPECT_U64("and its Length", 8U, (uint64_t)long_header.payload_len + 1U);
  }

  error = 0U;
  c = wt_cursor_init(k_bad_cid, sizeof(k_bad_cid));
  WT_EXPECT_STATUS("a 21-byte connection ID is refused", WT_ERR_PROTOCOL,
                   wt_quic_long_header_decode(&c, &long_header, &error));
  WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);

  /* Zero bytes of packet, and a packet truncated in the middle of every field. */
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("an empty buffer is truncated", WT_ERR_TRUNCATED,
                   wt_quic_long_header_decode(&c, &long_header, &error));
  {
    /* A well-formed Initial header except that the Length claims more than the buffer holds. */
    static const uint8_t k_short_payload[22] = {
        0xc3U, 0x00U, 0x00U, 0x00U, 0x01U, 0x08U, 0x83U, 0x94U, 0xc8U, 0xf0U, 0x3eU,
        0x51U, 0x57U, 0x08U, 0x00U, 0x00U, 0x44U, 0x9eU, 0x00U, 0x00U, 0x00U, 0x02U};
    c = wt_cursor_init(k_short_payload, sizeof(k_short_payload));
    WT_EXPECT_STATUS("a Length larger than the buffer is truncated", WT_ERR_TRUNCATED,
                     wt_quic_long_header_decode(&c, &long_header, &error));
  }
  /* Every prefix of a valid packet, which is the truncation corpus. The packet is one byte of first
   * byte, four of version, an eight-byte destination connection ID, an empty source connection ID, a
   * one-byte Length of 8, a one-byte packet number and seven bytes of payload: 24 bytes, each of
   * whose prefixes must be refused.
   *
   * The first byte is 0xe0: a Handshake packet (type 2) with a one-byte packet number. An Initial
   * would carry a token length field, which this vector does not have -- and the first version of it
   * did not, so the parser read the Length as a token length and then ran out of packet. */
  {
    static const uint8_t k_complete[24] = {0xe0U, 0x00U, 0x00U, 0x00U, 0x01U, 0x08U, 0x01U, 0x02U,
                                           0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x00U, 0x08U,
                                           0x01U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U};
    size_t cut;
    for (cut = 0U; cut < sizeof(k_complete); cut++) {
      c = wt_cursor_init(k_complete, cut);
      WT_EXPECT_STATUS("a prefix of a packet is truncated", WT_ERR_TRUNCATED,
                       wt_quic_long_header_decode(&c, &long_header, &error));
    }
    /* And the whole thing parses, so the corpus above is not refusing everything. */
    c = wt_cursor_init(k_complete, sizeof(k_complete));
    WT_EXPECT_STATUS("the complete packet parses", WT_OK,
                     wt_quic_long_header_decode(&c, &long_header, &error));
    WT_EXPECT_U64("with its packet number", 1U, long_header.packet_number);
    WT_EXPECT_U64("and its payload", 7U, (uint64_t)long_header.payload_len);
    WT_EXPECT_U64("and consumes the datagram", 24U, (uint64_t)long_header.total_len);
  }
}

/* Encoding refusals: the encoder will not build a packet the parser would refuse, and it computes
 * the Length so a caller cannot get it wrong. */
void test_the_encoding_refusals(void) {
  static const uint8_t k_id[21] = {0};
  static const uint8_t k_token[4] = {0};
  static const uint8_t k_payload[4] = {0};
  uint8_t buffer[64];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_quic_error_t error = 0U;

  WT_EXPECT_STATUS("a 21-byte connection ID cannot be encoded", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_long_header_encode(&w, WT_QUIC_PACKET_INITIAL, WT_QUIC_VERSION_1, k_id,
                                              21U, NULL, 0U, NULL, 0U, 1U, 1U, k_payload,
                                              sizeof(k_payload)));
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_STATUS("a token on a non-Initial packet is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1, NULL,
                                              0U, NULL, 0U, k_token, sizeof(k_token), 1U, 1U,
                                              k_payload, sizeof(k_payload)));
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_STATUS("a Retry type is refused by the long header encoder", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_long_header_encode(&w, WT_QUIC_PACKET_RETRY, WT_QUIC_VERSION_1, NULL, 0U,
                                              NULL, 0U, NULL, 0U, 1U, 1U, k_payload,
                                              sizeof(k_payload)));
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_STATUS("a five-byte packet number is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1, NULL,
                                              0U, NULL, 0U, NULL, 0U, 1U, 5U, k_payload,
                                              sizeof(k_payload)));
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_STATUS(
      "a short header with no packet number is refused", WT_ERR_INVALID_ARGUMENT,
      wt_quic_short_header_encode(&w, NULL, 0U, 1U, 0U, 0, 0, k_payload, sizeof(k_payload)));
  WT_EXPECT_STATUS("a NULL writer is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_long_header_encode(NULL, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1,
                                              NULL, 0U, NULL, 0U, NULL, 0U, 1U, 1U, k_payload,
                                              sizeof(k_payload)));
  /* A Short header whose connection ID length is above twenty is a caller's bug, since the length is
   * the caller's own. */
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_STATUS(
      "a short header refuses an over-long connection ID", WT_ERR_INVALID_ARGUMENT,
      wt_quic_short_header_encode(&w, k_id, 21U, 1U, 1U, 0, 0, k_payload, sizeof(k_payload)));
  /* A Retry needs a source connection ID: it is the one the server chose. */
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_STATUS("a Retry without a source connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, NULL, 0U, NULL, 0U, NULL, 0U,
                                               (const uint8_t *)buffer));
  WT_EXPECT_STATUS(
      "a NULL writer is refused by the short encoder", WT_ERR_INVALID_ARGUMENT,
      wt_quic_short_header_encode(NULL, NULL, 0U, 1U, 1U, 0, 0, k_payload, sizeof(k_payload)));
  WT_EXPECT_STATUS("a NULL cursor is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_long_header_decode(NULL, NULL, &error));
}
