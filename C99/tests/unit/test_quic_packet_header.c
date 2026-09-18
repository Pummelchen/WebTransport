/* The packet header round trips: RFC 9001 appendix A.2's client Initial, the first-byte
 * classification a multiplexer does, one encoded-and-decoded packet of each shape, a coalesced
 * datagram, and the packet-type names.
 *
 * These are the corpora the `ce1e708` split dropped from `test_quic_packet.c` when it extracted
 * four functions and discarded the file's `main` body. The assertions are the original ones against
 * the current source; where the audit changed a behaviour the test follows the source, not the old
 * text. */

#include "test_quic_packet_internal.h"

/* RFC 9001 appendix A.2's client Initial header, printed as
 * `c300000001088394c8f03e5157080000449e00000002`: a long header, type Initial, version 1, an
 * 8-byte destination connection ID, an empty source connection ID, an empty token, a Length of 1182
 * and a 4-byte packet number of 2. Decoding it and re-encoding it byte for byte is a check against
 * the RFC's bytes rather than against this code. */
void test_the_rfc9001_a2_client_initial_header(void) {
  static const uint8_t k_rfc_header[22] = {0xc3U, 0x00U, 0x00U, 0x00U, 0x01U, 0x08U, 0x83U, 0x94U,
                                           0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x08U, 0x00U, 0x00U,
                                           0x44U, 0x9eU, 0x00U, 0x00U, 0x00U, 0x02U};
  uint8_t buffer[2048];
  wt_quic_long_header_t long_header;
  wt_cursor_t c;
  wt_quic_error_t error = 0U;

  /* The packet's Length field says 1182 bytes follow the packet number, so a cursor over just the
   * header cannot contain the packet -- the header is parsed from a packet, and the block below
   * supplies a payload of the right size. Here only the fields up to the Length are checked. */
  c = wt_cursor_init(k_rfc_header, sizeof(k_rfc_header));
  WT_EXPECT_STATUS("the RFC's header parses as far as the length", WT_ERR_TRUNCATED,
                   wt_quic_long_header_decode(&c, &long_header, &error));

  /* The whole packet: the RFC's header plus 1178 bytes of payload (1182 minus the 4-byte packet
   * number) so that the Length is satisfied. */
  {
    uint8_t packet[22U + 1178U];
    size_t i;
    for (i = 0U; i < sizeof(k_rfc_header); i++)
      packet[i] = k_rfc_header[i];
    for (i = 0U; i < 1178U; i++)
      packet[22U + i] = 0xABU;

    c = wt_cursor_init(packet, sizeof(packet));
    WT_EXPECT_STATUS("the RFC's Initial header parses", WT_OK,
                     wt_quic_long_header_decode(&c, &long_header, &error));
    WT_EXPECT_INT("it is an Initial", (long)WT_QUIC_PACKET_INITIAL, (long)long_header.type);
    WT_EXPECT_U64("of version 1", WT_QUIC_VERSION_1, long_header.version);
    WT_EXPECT_U64("with an 8-byte destination connection ID", 8U,
                  (uint64_t)long_header.destination_connection_id_len);
    WT_EXPECT_BYTES("which is the RFC's", (const uint8_t *)"\x83\x94\xc8\xf0\x3e\x51\x57\x08",
                    long_header.destination_connection_id, 8U);
    WT_EXPECT_U64("an empty source connection ID", 0U,
                  (uint64_t)long_header.source_connection_id_len);
    WT_EXPECT_U64("an empty token", 0U, (uint64_t)long_header.token_len);
    WT_EXPECT_U64("a 4-byte packet number", 4U, (uint64_t)long_header.packet_number_len);
    WT_EXPECT_U64("whose value is 2", 2U, long_header.packet_number);
    WT_EXPECT_U64("a payload of 1178 bytes", 1178U, (uint64_t)long_header.payload_len);
    WT_EXPECT_U64("and 22 bytes of header", 22U, (uint64_t)long_header.header_len);
    WT_EXPECT_U64("so the packet is 1200 bytes", 1200U, (uint64_t)long_header.total_len);
    WT_EXPECT_INT("the cursor consumed the whole packet", 1, wt_cursor_at_end(&c));
    /* The header view is what RFC 9001 section 5.3 authenticates, so it must be the first 22 bytes
     * and no more. */
    WT_EXPECT_BYTES("the authenticated header is the RFC's", k_rfc_header, long_header.header, 22U);

    /* Re-encoding reproduces the RFC's bytes exactly. */
    {
      wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
      WT_EXPECT_STATUS(
          "the header re-encodes", WT_OK,
          wt_quic_long_header_encode(
              &w, long_header.type, long_header.version, long_header.destination_connection_id,
              long_header.destination_connection_id_len, long_header.source_connection_id,
              long_header.source_connection_id_len, long_header.token, long_header.token_len,
              long_header.packet_number, long_header.packet_number_len, long_header.payload,
              long_header.payload_len));
      WT_EXPECT_U64("to the RFC's 1200 bytes", 1200U, (uint64_t)wt_writer_offset(&w));
      WT_EXPECT_BYTES("and the RFC's first 22 bytes", k_rfc_header, buffer, 22U);
      WT_EXPECT_BYTES("with the payload after them", packet + 22U, buffer + 22U, 1178U);
    }
  }
}

/* The first-byte classification, which is what a multiplexer does before it knows anything else. */
void test_the_first_byte_classification(void) {
  static const uint8_t k_long_packet[5] = {0xc0U, 0x00U, 0x00U, 0x00U, 0x01U};
  static const uint8_t k_short_packet[5] = {0x40U, 0x01U, 0x02U, 0x03U, 0x04U};
  static const uint8_t k_version_negotiation[5] = {0xc0U, 0x00U, 0x00U, 0x00U, 0x00U};
  wt_quic_packet_kind_t kind = WT_QUIC_PACKET_KIND_SHORT;

  WT_EXPECT_STATUS("a long header is classified", WT_OK,
                   wt_quic_packet_kind(k_long_packet, sizeof(k_long_packet), &kind));
  WT_EXPECT_INT("as long", (long)WT_QUIC_PACKET_KIND_LONG, (long)kind);
  WT_EXPECT_STATUS("a short header is classified", WT_OK,
                   wt_quic_packet_kind(k_short_packet, sizeof(k_short_packet), &kind));
  WT_EXPECT_INT("as short", (long)WT_QUIC_PACKET_KIND_SHORT, (long)kind);
  WT_EXPECT_STATUS(
      "version zero is classified", WT_OK,
      wt_quic_packet_kind(k_version_negotiation, sizeof(k_version_negotiation), &kind));
  WT_EXPECT_INT("as version negotiation", (long)WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION,
                (long)kind);
  WT_EXPECT_STATUS("an empty datagram has no packet", WT_ERR_TRUNCATED,
                   wt_quic_packet_kind(NULL, 0U, &kind));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_kind(k_short_packet, 5U, NULL));
  /* A long header that stops before its version cannot be classified. */
  WT_EXPECT_STATUS("three bytes of long header is truncated", WT_ERR_TRUNCATED,
                   wt_quic_packet_kind(k_long_packet, 3U, &kind));
}

/* A handshake packet with a 2-byte packet number, a token of zero length and a source connection ID,
 * encoded and decoded. */
void test_a_handshake_packet_round_trips(void) {
  static const uint8_t k_dcid[4] = {1U, 2U, 3U, 4U};
  static const uint8_t k_scid[2] = {5U, 6U};
  static const uint8_t k_payload[8] = {0xAAU, 0xBBU, 0xCCU, 0xDDU, 0x11U, 0x22U, 0x33U, 0x44U};
  uint8_t buffer[64];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_quic_long_header_t decoded;
  wt_cursor_t c;
  wt_quic_error_t error = 0U;

  WT_EXPECT_STATUS("a handshake packet encodes", WT_OK,
                   wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1,
                                              k_dcid, sizeof(k_dcid), k_scid, sizeof(k_scid), NULL,
                                              0U, 0x1234U, 2U, k_payload, sizeof(k_payload)));
  WT_EXPECT_U64("to a byte more than its header and payload",
                1U + 4U + 1U + sizeof(k_dcid) + 1U + sizeof(k_scid) + 1U + 2U + sizeof(k_payload),
                (uint64_t)wt_writer_offset(&w));
  c = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_STATUS("and decodes", WT_OK, wt_quic_long_header_decode(&c, &decoded, &error));
  WT_EXPECT_U64("with the packet number reconstructed from two bytes", 0x1234U,
                decoded.packet_number);
  WT_EXPECT_BYTES("and its payload", k_payload, decoded.payload, sizeof(k_payload));
  WT_EXPECT_U64("the destination connection ID survives", sizeof(k_dcid),
                (uint64_t)decoded.destination_connection_id_len);
  WT_EXPECT_U64("and the source", sizeof(k_scid), (uint64_t)decoded.source_connection_id_len);
}

/* An Initial packet carries a token, and the token's length is a varint. */
void test_an_initial_with_a_large_token_round_trips(void) {
  static const uint8_t k_dcid[8] = {9U, 9U, 9U, 9U, 9U, 9U, 9U, 9U};
  static const uint8_t k_token[300] = {0};
  static const uint8_t k_payload[4] = {1U, 2U, 3U, 4U};
  uint8_t buffer[512];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_quic_long_header_t decoded;
  wt_cursor_t c;
  wt_quic_error_t error = 0U;

  WT_EXPECT_STATUS("an Initial with a 300-byte token encodes", WT_OK,
                   wt_quic_long_header_encode(&w, WT_QUIC_PACKET_INITIAL, WT_QUIC_VERSION_1, k_dcid,
                                              sizeof(k_dcid), NULL, 0U, k_token, sizeof(k_token),
                                              1U, 1U, k_payload, sizeof(k_payload)));
  c = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_STATUS("and decodes", WT_OK, wt_quic_long_header_decode(&c, &decoded, &error));
  WT_EXPECT_U64("with the token length", sizeof(k_token), (uint64_t)decoded.token_len);
  /* The token view points into the packet: one byte of first byte, four of version, a one-byte
   * destination connection ID length and eight of ID, a one-byte source connection ID length, and
   * the token's own two-byte varint length, which is where the token starts. */
  WT_EXPECT_TRUE("the token view points inside the packet",
                 decoded.token >= buffer && decoded.token < buffer + wt_writer_offset(&w));
  WT_EXPECT_U64("at the offset the header implies", 1U + 4U + 1U + 8U + 1U + 2U,
                (uint64_t)(decoded.token - buffer));
}

/* A short header. Its connection ID length is the caller's, because the wire does not carry it. */
void test_a_short_header_round_trips(void) {
  static const uint8_t k_dcid[8] = {1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U};
  static const uint8_t k_payload[6] = {7U, 7U, 7U, 7U, 7U, 7U};
  uint8_t buffer[64];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_quic_short_header_t decoded;
  wt_cursor_t c;
  wt_quic_error_t error = 0U;

  WT_EXPECT_STATUS("a short header encodes", WT_OK,
                   wt_quic_short_header_encode(&w, k_dcid, sizeof(k_dcid), 0xABCDU, 2U, 1, 0,
                                               k_payload, sizeof(k_payload)));
  WT_EXPECT_TRUE("with the fixed bit set", (buffer[0] & WT_QUIC_FIXED_BIT) != 0U);
  WT_EXPECT_TRUE("and the long header bit clear", (buffer[0] & WT_QUIC_LONG_HEADER_BIT) == 0U);
  WT_EXPECT_TRUE("and the key phase set", (buffer[0] & WT_QUIC_KEY_PHASE_BIT) != 0U);
  WT_EXPECT_TRUE("and the spin bit clear", (buffer[0] & WT_QUIC_SPIN_BIT) == 0U);
  c = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_STATUS("and decodes", WT_OK,
                   wt_quic_short_header_decode(&c, sizeof(k_dcid), &decoded, &error));
  WT_EXPECT_U64("with its packet number", 0xABCDU, decoded.packet_number);
  WT_EXPECT_INT("its key phase", 1, decoded.key_phase);
  WT_EXPECT_INT("its spin bit", 0, decoded.spin);
  WT_EXPECT_BYTES("its connection ID", k_dcid, decoded.destination_connection_id, sizeof(k_dcid));
  WT_EXPECT_BYTES("and a payload that runs to the end", k_payload, decoded.payload,
                  sizeof(k_payload));
}

/* A coalesced datagram: an Initial then a Handshake, walked by the reported sizes. */
void test_a_coalesced_datagram_walks_by_reported_sizes(void) {
  static const uint8_t k_payload_a[4] = {1U, 2U, 3U, 4U};
  static const uint8_t k_payload_b[3] = {5U, 6U, 7U};
  uint8_t datagram[256];
  wt_writer_t w = wt_writer_init(datagram, sizeof(datagram));
  wt_quic_long_header_t first;
  wt_quic_long_header_t second;
  wt_cursor_t c;
  wt_quic_error_t error = 0U;
  size_t first_len;

  (void)wt_quic_long_header_encode(&w, WT_QUIC_PACKET_INITIAL, WT_QUIC_VERSION_1, NULL, 0U, NULL,
                                   0U, NULL, 0U, 1U, 1U, k_payload_a, sizeof(k_payload_a));
  first_len = wt_writer_offset(&w);
  (void)wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1, NULL, 0U, NULL,
                                   0U, NULL, 0U, 1U, 1U, k_payload_b, sizeof(k_payload_b));
  c = wt_cursor_init(datagram, wt_writer_offset(&w));
  WT_EXPECT_STATUS("the first coalesced packet parses", WT_OK,
                   wt_quic_long_header_decode(&c, &first, &error));
  WT_EXPECT_INT("it is the Initial", (long)WT_QUIC_PACKET_INITIAL, (long)first.type);
  WT_EXPECT_U64("and its size is where the next one starts", (uint64_t)first_len,
                (uint64_t)first.total_len);
  WT_EXPECT_STATUS("the second parses where the first ended", WT_OK,
                   wt_quic_long_header_decode(&c, &second, &error));
  WT_EXPECT_INT("it is the Handshake", (long)WT_QUIC_PACKET_HANDSHAKE, (long)second.type);
  WT_EXPECT_BYTES("with its own payload", k_payload_b, second.payload, sizeof(k_payload_b));
  WT_EXPECT_INT("and the datagram is consumed", 1, wt_cursor_at_end(&c));
}

/* The names a log prints for a packet type. */
void test_the_packet_type_names(void) {
  WT_EXPECT_STR("initial", "initial", wt_quic_packet_type_name(WT_QUIC_PACKET_INITIAL));
  WT_EXPECT_STR("0-rtt", "0-rtt", wt_quic_packet_type_name(WT_QUIC_PACKET_ZERO_RTT));
  WT_EXPECT_STR("handshake", "handshake", wt_quic_packet_type_name(WT_QUIC_PACKET_HANDSHAKE));
  WT_EXPECT_STR("retry", "retry", wt_quic_packet_type_name(WT_QUIC_PACKET_RETRY));
  WT_EXPECT_STR("unknown", "unknown", wt_quic_packet_type_name((wt_quic_packet_type_t)9));
}
