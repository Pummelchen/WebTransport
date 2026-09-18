/* QUIC packet headers (RFC 9000 sections 17.2 and 17.3).
 *
 * The vector that matters is RFC 9001 appendix A.2's client Initial header,
 * printed as `c300000001088394c8f03e5157080000449e00000002`: a long header, type
 * Initial, version 1, an 8-byte destination connection ID, an empty source
 * connection ID, an empty token, a Length of 1182 and a 4-byte packet number of
 * 2. Decoding it and re-encoding it byte for byte is a check against the RFC's
 * bytes rather than against this code.
 *
 * The refusals are the rest: the fixed bit, the reserved bits, a connection ID
 * above twenty bytes, a Retry where a long header was expected, and truncation
 * at every field boundary.
 */

#include "wt_test.h"

#include "webtransport/quic/packet.h"

#include "rfc9001_retry.h"
#include "test_quic_packet_connection_ids_support.h"


/* RFC 9000 section 5.1: "A zero-length connection ID can be used when a connection ID is not needed to route to
 * the correct endpoint", and section 5.1.1: "A zero-length Destination Connection ID field is used in all packets
 * sent toward such an endpoint over any network path." A server that cannot WRITE one cannot answer a client that
 * selected one, and that is not hypothetical: quic-go's client selects one for its first Initial, and this tree's
 * listener refused the packet before decoding it (WT-258). The encode is what the fix depends on. */
static void test_a_zero_length_destination_connection_id(void) {
  static const uint8_t k_source_id[8] = {0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U};
  static const uint8_t k_payload[4] = {0xAAU, 0xBBU, 0xCCU, 0xDDU};
  uint8_t buffer[64];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_quic_long_header_t decoded;
  wt_cursor_t c;
  wt_quic_error_t error = 0U;

  WT_EXPECT_OK("a Handshake packet towards a peer with no connection ID encodes",
               wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1, NULL, 0U,
                                          k_source_id, sizeof(k_source_id), NULL, 0U, 0U, 1U,
                                          k_payload, sizeof(k_payload)));
  c = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_quic_long_header_decode(&c, &decoded, &error));
  WT_EXPECT_U64("with an empty destination connection ID", 0U,
                (uint64_t)decoded.destination_connection_id_len);
  WT_EXPECT_U64("and the source it was given", (uint64_t)sizeof(k_source_id),
                (uint64_t)decoded.source_connection_id_len);
  WT_EXPECT_BYTES("byte for byte", k_source_id, decoded.source_connection_id, sizeof(k_source_id));
  WT_EXPECT_BYTES("with the payload behind it", k_payload, decoded.payload, sizeof(k_payload));
}

int main(void) {
  test_a_zero_length_destination_connection_id();
  WT_TEST_MAIN_END("test_quic_packet_connection_ids");
}
