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

/* A listener peeks the FRONT of a datagram, so the two connection IDs must be readable from a prefix of a long
 * header -- which `wt_quic_long_header_decode` cannot do, because it also reads the Length field and hands back
 * a view of the payload. Requiring the whole packet there meant a 1200-byte Initial could not be read from a
 * 64-byte peek, and a server that peeked before arming its connection therefore accepted nothing at all
 * (WT-151). */
static void test_the_connection_ids_of_a_long_header_can_be_read_from_a_prefix(void) {
  static const uint8_t k_destination[8] = {0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U};
  static const uint8_t k_source[4] = {0xaaU, 0xbbU, 0xccU, 0xddU};
  uint8_t packet[64];
  uint8_t truncated[8];
  const uint8_t *destination = NULL;
  const uint8_t *source = NULL;
  size_t destination_length = 0U;
  size_t source_length = 0U;
  wt_writer_t w = wt_writer_init(packet, sizeof(packet));

  /* A long header: first byte 0xc0 (long, fixed, Initial, packet number length one), version 1, then the two
   * IDs with their length bytes. The rest of the packet is deliberately absent: this is a PREFIX. */
  wt_writer_u8(&w, 0xc0U);
  wt_writer_u32(&w, WT_QUIC_VERSION_1);
  wt_writer_u8(&w, (uint8_t)sizeof(k_destination));
  wt_writer_bytes(&w, k_destination, sizeof(k_destination));
  wt_writer_u8(&w, (uint8_t)sizeof(k_source));
  wt_writer_bytes(&w, k_source, sizeof(k_source));
  WT_EXPECT_TRUE("the prefix is shorter than a packet", wt_writer_offset(&w) < 32U);

  WT_EXPECT_OK("the IDs read from the prefix",
               wt_quic_long_header_connection_ids(packet, wt_writer_offset(&w), &destination,
                                                  &destination_length, &source, &source_length));
  WT_EXPECT_U64("with the destination's length", (uint64_t)sizeof(k_destination),
                (uint64_t)destination_length);
  WT_EXPECT_BYTES("and its bytes", k_destination, destination, sizeof(k_destination));
  WT_EXPECT_U64("the source's length", (uint64_t)sizeof(k_source), (uint64_t)source_length);
  WT_EXPECT_BYTES("and its bytes", k_source, source, sizeof(k_source));

  /* A prefix that stops inside the source ID is not a header: truncation is the answer, not a guess. */
  WT_EXPECT_STATUS("a prefix that stops inside the source ID is truncated", WT_ERR_TRUNCATED,
                   wt_quic_long_header_connection_ids(
                       packet, 16U, &destination, &destination_length, &source, &source_length));
  /* A short header has no long-header IDs: its destination ID is the length the receiver already knows. */
  {
    uint8_t short_packet[16];
    memset(short_packet, 0, sizeof(short_packet));
    short_packet[0] = 0x40U;
    WT_EXPECT_STATUS("and a short header is not one", WT_ERR_PROTOCOL,
                     wt_quic_long_header_connection_ids(short_packet, sizeof(short_packet),
                                                        &destination, &destination_length, &source,
                                                        &source_length));
  }
  /* A missing fixed bit is not a version-1 packet at all (RFC 9000 section 17.2). */
  truncated[0] = 0x80U;
  WT_EXPECT_STATUS("as is a long header without the fixed bit", WT_ERR_PROTOCOL,
                   wt_quic_long_header_connection_ids(truncated, sizeof(truncated), &destination,
                                                      &destination_length, &source,
                                                      &source_length));
  WT_EXPECT_STATUS("and a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_long_header_connection_ids(packet, wt_writer_offset(&w), NULL,
                                                      &destination_length, &source,
                                                      &source_length));
}

/* RFC 9000 section 17.2.5 puts an `Unused (4)` field where the protected packet types put the reserved bits and
 * the packet number length, and says of it: "The value in the Unused field is set to an arbitrary value by the
 * server; a client MUST ignore these bits." RFC 9001 appendix A.4's Retry therefore begins 0xff -- Unused =
 * 0xf -- and it is the very packet the integrity tag is computed over, so a client that refuses it refuses the
 * RFC's own example. Applying the protected types' reserved-bit rule (section 17.2) to a Retry was exactly
 * that mistake, and a vector this repository already ships is the check that catches it: the RFC's bytes say
 * what must be accepted, and a rule this code invented cannot overrule them. The other three nibbles are
 * covered too, because the bug refused only the 0x0c half of the field. */
static void test_a_retry_ignores_the_unused_bits(void) {
  wt_quic_retry_packet_t decoded;
  wt_quic_error_t error = 0U;
  uint8_t unused_bits;

  WT_EXPECT_U64("the RFC's Retry has non-zero Unused bits", 0x0fU,
                (uint64_t)(WT_RFC9001_RETRY_PACKET[0] & 0x0fU));
  WT_EXPECT_STATUS("and a client accepts it", WT_OK,
                   wt_quic_retry_packet_decode(WT_RFC9001_RETRY_PACKET, WT_RFC9001_RETRY_PACKET_LEN,
                                               &decoded, &error));
  WT_EXPECT_U64("with the five-byte token A.4 prints", 5U, (uint64_t)decoded.token_len);
  WT_EXPECT_BYTES("byte for byte", (const uint8_t *)"token", decoded.token, 5U);
  WT_EXPECT_BYTES("and the tag A.4 prints", WT_RFC9001_RETRY_TAG, decoded.integrity_tag,
                  WT_RFC9001_RETRY_TAG_LEN);

  /* Every value of the field, not just the RFC's: a Retry is a whole datagram whose shape the other fields
   * already fix, so the only thing the first byte's low nibble may do is fail this test. The packet is the
   * RFC's own, with nothing but that nibble changed. */
  for (unused_bits = 0U; unused_bits < 16U; unused_bits++) {
    uint8_t varied[WT_RFC9001_RETRY_PACKET_LEN];
    wt_quic_retry_packet_t one;
    memcpy(varied, WT_RFC9001_RETRY_PACKET, sizeof(varied));
    varied[0] = (uint8_t)(0xf0U | unused_bits);
    WT_EXPECT_STATUS("a Retry whose Unused field is arbitrary parses", WT_OK,
                     wt_quic_retry_packet_decode(varied, sizeof(varied), &one, &error));
    WT_EXPECT_U64("with its token intact", 5U, (uint64_t)one.token_len);
    WT_EXPECT_BYTES("and its tag last", WT_RFC9001_RETRY_TAG, one.integrity_tag,
                    WT_RFC9001_RETRY_TAG_LEN);
  }
}

/* A non-zero length with a NULL pointer is a caller error, and the writer would read it; the long header
 * encoder refuses exactly these arguments (`packet.c`, `wt_quic_long_header_encode`), and a public Retry
 * encoder that segfaults instead is a defect a caller cannot defend against (WT-239). Nothing may be written
 * before the refusal either, or the caller is left with half a packet. */
static void test_a_retry_encoder_refuses_missing_argument_bytes(void) {
  static const uint8_t k_source[1] = {0x77U};
  static const uint8_t k_token[3] = {0xA1U, 0xA2U, 0xA3U};
  static const uint8_t k_tag[16] = {0};
  uint8_t buffer[64];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));

  WT_EXPECT_STATUS("a NULL destination connection ID with a length is refused",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, NULL, 4U, k_source,
                                               sizeof(k_source), k_token, sizeof(k_token), k_tag));
  WT_EXPECT_STATUS("a NULL token with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, NULL, 0U, k_source,
                                               sizeof(k_source), NULL, 4U, k_tag));
  WT_EXPECT_U64("and neither refusal wrote a byte", 0U, (uint64_t)wt_writer_offset(&w));

  /* The zero-length forms of the same arguments are legal: a Retry may carry no destination connection ID at
   * all, and a zero-length token is a packet the client discards rather than a caller error. */
  WT_EXPECT_STATUS("a zero-length destination connection ID is legal", WT_OK,
                   wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, NULL, 0U, k_source,
                                               sizeof(k_source), k_token, sizeof(k_token), k_tag));
  WT_EXPECT_U64("and it wrote the packet",
                (uint64_t)(1U + 4U + 1U + 0U + 1U + sizeof(k_source) + sizeof(k_token) + 16U),
                (uint64_t)wt_writer_offset(&w));
}

/* AUD-0023. RFC 9000 section 17.2.1 makes the low bits of a Version Negotiation packet's first byte
 * ARBITRARY, so its type bits can read as Initial -- and before the fix `wt_quic_initial_token` read its
 * version list as a Token Length field and accepted a one-byte token from a packet that is not an Initial at
 * all. This is a full Version Negotiation packet -- connection IDs and a version list -- unlike the five-byte
 * classifier fixture, which stops before the token. The function must refuse version zero with the code the
 * source returns for it, WT_ERR_PROTOCOL (`wt_quic_initial_token`, src/quic/packet.c), and report no token. The
 * other two long-header walkers are pinned beside it so all three answers for a Version Negotiation are
 * asserted in one place. */
static void test_a_version_negotiation_is_not_an_initial(void) {
  static const uint8_t k_version_negotiation[] = {
      0xc0U,                                                  /* long header, fixed, type 00 */
      0x00U, 0x00U, 0x00U, 0x00U,                             /* version zero */
      0x04U, 0x01U, 0x02U, 0x03U, 0x04U,                      /* destination connection ID */
      0x04U, 0x05U, 0x06U, 0x07U, 0x08U,                      /* source connection ID */
      0x80U, 0x00U, 0x00U, 0x01U, 0xaaU, 0xbbU, 0xccU, 0xddU, /* supported versions */
  };
  wt_quic_packet_kind_t kind = WT_QUIC_PACKET_KIND_LONG;
  const uint8_t *token = NULL;
  size_t token_length = 0U;

  WT_EXPECT_STATUS(
      "a full version negotiation is classified", WT_OK,
      wt_quic_packet_kind(k_version_negotiation, sizeof(k_version_negotiation), &kind));
  WT_EXPECT_INT("  as version negotiation", (long)WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION,
                (long)kind);
  WT_EXPECT_STATUS("a version negotiation is not an Initial", WT_ERR_PROTOCOL,
                   wt_quic_initial_token(k_version_negotiation, sizeof(k_version_negotiation),
                                         &token, &token_length));
  WT_EXPECT_INT("  leaving no token length", 0, (long)token_length);
  WT_EXPECT_TRUE("  and no token", token == NULL);
  /* The packet-number walk refuses version zero too, and that guard is older than the fix -- it is the one
   * `wt_quic_initial_token` was missing. */
  {
    size_t offset = 0U;
    size_t total = 0U;
    int short_header = 1;
    WT_EXPECT_STATUS("and the packet-number walk refuses it", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_protected_pn_offset(k_version_negotiation,
                                                 sizeof(k_version_negotiation), 0U, &offset, &total,
                                                 &short_header));
  }
  /* The connection-ID reader accepts it, deliberately: RFC 9000 section 17.2.1 puts a Version Negotiation's
   * connection IDs at the same offsets as any other long header, so reading them is correct -- and this
   * function reports no version, so it is not the place that decides. The decision belongs to
   * `wt_quic_initial_token` above, which is why the two are asserted together. */
  {
    const uint8_t *destination = NULL;
    const uint8_t *source = NULL;
    size_t destination_length = 0U;
    size_t source_length = 0U;
    WT_EXPECT_STATUS("the connection-ID reader reads its IDs", WT_OK,
                     wt_quic_long_header_connection_ids(
                         k_version_negotiation, sizeof(k_version_negotiation), &destination,
                         &destination_length, &source, &source_length));
    WT_EXPECT_INT("  the destination as the VN packet spells it", 4, (long)destination_length);
    WT_EXPECT_INT("  and the source", 4, (long)source_length);
  }
}

/* The two guards `wt_quic_initial_token` applies before it reads anything: the header form and the fixed bit
 * together, then the packet type. AUD-0029: both are reachable from the server, which peeks the token of
 * whatever a peer sends (`runtime/server_retry.c`). A well-formed Initial sits behind each first byte, so the
 * FIRST BYTE IS THE MESSAGE'S ONLY FAULT -- with either guard deleted the parse continues, succeeds, and this
 * test fails. */
static void test_the_leading_guards_of_initial_token(void) {
  static const uint8_t k_body[] = {0x00U, 0x00U, 0x00U, 0x01U, 0x04U, 0x01U, 0x02U, 0x03U,
                                   0x04U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x00U};
  static const struct {
    const char *label;
    uint8_t first;
  } cases[] = {
      {"a short header is not an Initial", 0x40U}, /* the long header bit is clear */
      {"a long header without the fixed bit is refused", 0x80U},
      {"a Handshake long header is not an Initial", 0xe0U}, /* type bits 10 */
  };
  uint8_t message[sizeof(k_body) + 1U];
  const uint8_t *token = NULL;
  size_t token_length = 0U;
  size_t i;

  /* The unmodified first byte parses, so each refusal below is about the byte and not the body. */
  message[0] = 0xc0U;
  memcpy(message + 1U, k_body, sizeof(k_body));
  WT_EXPECT_OK("a well-formed Initial is accepted for the guard checks",
               wt_quic_initial_token(message, sizeof(message), &token, &token_length));
  for (i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
    message[0] = cases[i].first;
    WT_EXPECT_STATUS(cases[i].label, WT_ERR_PROTOCOL,
                     wt_quic_initial_token(message, sizeof(message), &token, &token_length));
  }
}

int main(void) {
  test_the_connection_ids_of_a_long_header_can_be_read_from_a_prefix();
  test_a_retry_ignores_the_unused_bits();
  test_a_retry_encoder_refuses_missing_argument_bytes();
  test_a_version_negotiation_is_not_an_initial();
  test_the_leading_guards_of_initial_token();
  WT_TEST_MAIN_END("test_quic_packet");
}
