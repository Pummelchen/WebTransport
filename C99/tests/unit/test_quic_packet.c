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
  /* Big enough for the RFC's 1200-byte packet, which is re-encoded into it. */
  uint8_t buffer[2048];
  wt_cursor_t c;
  wt_quic_error_t error = 0U;
  wt_status_t status;

  /* RFC 9001 appendix A.2's client Initial header. */
  {
    static const uint8_t header[22] = {0xc3U, 0x00U, 0x00U, 0x00U, 0x01U, 0x08U, 0x83U, 0x94U,
                                       0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x08U, 0x00U, 0x00U,
                                       0x44U, 0x9eU, 0x00U, 0x00U, 0x00U, 0x02U};
    wt_quic_long_header_t long_header;
    c = wt_cursor_init(header, sizeof(header));
    /* The packet's Length field says 1182 bytes follow the packet number, so a
     * cursor over just the header cannot contain the packet -- the header is
     * parsed from a packet, and this test supplies a payload of the right size
     * below. Here only the fields up to the Length are checked. */
    status = wt_quic_long_header_decode(&c, &long_header, &error);
    WT_EXPECT_STATUS("the RFC's header parses as far as the length", WT_ERR_TRUNCATED, status);
  }
  {
    /* The whole packet: the RFC's header plus 1178 bytes of payload (1182 minus
     * the 4-byte packet number) so that the Length is satisfied. */
    static const uint8_t rfc_header[22] = {0xc3U, 0x00U, 0x00U, 0x00U, 0x01U, 0x08U, 0x83U, 0x94U,
                                           0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x08U, 0x00U, 0x00U,
                                           0x44U, 0x9eU, 0x00U, 0x00U, 0x00U, 0x02U};
    uint8_t packet[22U + 1178U];
    wt_quic_long_header_t long_header;
    size_t i;
    for (i = 0U; i < sizeof(rfc_header); i++)
      packet[i] = rfc_header[i];
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
    /* The header view is what RFC 9001 section 5.3 authenticates, so it must be
     * the first 22 bytes and no more. */
    WT_EXPECT_BYTES("the authenticated header is the RFC's", rfc_header, long_header.header, 22U);

    /* Re-encoding reproduces the RFC's bytes exactly. */
    {
      wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
      status = wt_quic_long_header_encode(
          &w, long_header.type, long_header.version, long_header.destination_connection_id,
          long_header.destination_connection_id_len, long_header.source_connection_id,
          long_header.source_connection_id_len, long_header.token, long_header.token_len,
          long_header.packet_number, long_header.packet_number_len, long_header.payload,
          long_header.payload_len);
      WT_EXPECT_STATUS("the header re-encodes", WT_OK, status);
      WT_EXPECT_U64("to the RFC's 1200 bytes", 1200U, (uint64_t)wt_writer_offset(&w));
      WT_EXPECT_BYTES("and the RFC's first 22 bytes", rfc_header, buffer, 22U);
      WT_EXPECT_BYTES("with the payload after them", packet + 22U, buffer + 22U, 1178U);
    }
  }

  /* The first-byte classification, which is what a multiplexer does before it
   * knows anything else. */
  {
    static const uint8_t long_packet[5] = {0xc0U, 0x00U, 0x00U, 0x00U, 0x01U};
    static const uint8_t short_packet[5] = {0x40U, 0x01U, 0x02U, 0x03U, 0x04U};
    static const uint8_t version_negotiation[5] = {0xc0U, 0x00U, 0x00U, 0x00U, 0x00U};
    wt_quic_packet_kind_t kind = WT_QUIC_PACKET_KIND_SHORT;
    WT_EXPECT_STATUS("a long header is classified", WT_OK,
                     wt_quic_packet_kind(long_packet, sizeof(long_packet), &kind));
    WT_EXPECT_INT("as long", (long)WT_QUIC_PACKET_KIND_LONG, (long)kind);
    WT_EXPECT_STATUS("a short header is classified", WT_OK,
                     wt_quic_packet_kind(short_packet, sizeof(short_packet), &kind));
    WT_EXPECT_INT("as short", (long)WT_QUIC_PACKET_KIND_SHORT, (long)kind);
    WT_EXPECT_STATUS("version zero is classified", WT_OK,
                     wt_quic_packet_kind(version_negotiation, sizeof(version_negotiation), &kind));
    WT_EXPECT_INT("as version negotiation", (long)WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION,
                  (long)kind);
    WT_EXPECT_STATUS("an empty datagram has no packet", WT_ERR_TRUNCATED,
                     wt_quic_packet_kind(NULL, 0U, &kind));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_packet_kind(short_packet, 5U, NULL));
    /* A long header that stops before its version cannot be classified. */
    WT_EXPECT_STATUS("three bytes of long header is truncated", WT_ERR_TRUNCATED,
                     wt_quic_packet_kind(long_packet, 3U, &kind));

    /* AUD-0023. RFC 9000 section 17.2.1 makes the low bits of a Version Negotiation's first
     * byte arbitrary, so the 0xc0 above gives it Initial's type bits. The five-byte fixture is
     * too short to reach the token; this one carries connection IDs and a version list, and
     * before the fix `wt_quic_initial_token` read the version list as a Token Length field and
     * accepted a one-byte token -- from a packet that is not an Initial at all. */
    {
      static const uint8_t full_version_negotiation[] = {
          0xc0U,                                                  /* long header, fixed, type 00 */
          0x00U, 0x00U, 0x00U, 0x00U,                             /* version zero */
          0x04U, 0x01U, 0x02U, 0x03U, 0x04U,                      /* destination connection ID */
          0x04U, 0x05U, 0x06U, 0x07U, 0x08U,                      /* source connection ID */
          0x80U, 0x00U, 0x00U, 0x01U, 0xaaU, 0xbbU, 0xccU, 0xddU, /* supported versions */
      };
      const uint8_t *token = NULL;
      size_t token_length = 0U;
      WT_EXPECT_STATUS(
          "a full version negotiation is classified", WT_OK,
          wt_quic_packet_kind(full_version_negotiation, sizeof(full_version_negotiation), &kind));
      WT_EXPECT_INT("  as version negotiation", (long)WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION,
                    (long)kind);
      WT_EXPECT_STATUS("a version negotiation is not an Initial", WT_ERR_PROTOCOL,
                       wt_quic_initial_token(full_version_negotiation,
                                             sizeof(full_version_negotiation), &token,
                                             &token_length));
      WT_EXPECT_INT("  leaving no token length", 0, (long)token_length);
      WT_EXPECT_TRUE("  and no token", token == NULL);
      /* The third long-header walker refuses version zero too, and that guard is older than this
       * test -- it is the one `wt_quic_initial_token` was missing. Pinned here so all three
       * walkers' answers for a Version Negotiation are asserted in one place. */
      {
        size_t offset = 0U;
        size_t total = 0U;
        int short_header = 1;
        WT_EXPECT_STATUS("and the packet-number walk refuses it", WT_ERR_INVALID_ARGUMENT,
                         wt_quic_protected_pn_offset(full_version_negotiation,
                                                     sizeof(full_version_negotiation), 0U, &offset,
                                                     &total, &short_header));
      }
      /* The connection-ID reader accepts it, deliberately: RFC 9000 section 17.2.1 puts a Version
       * Negotiation's connection IDs at the same offsets as any other long header, so reading them
       * is correct -- and this function reports no version, so it is not the place that decides.
       * The decision belongs to `wt_quic_initial_token` above, which is why the two are asserted
       * together. */
      {
        const uint8_t *destination = NULL;
        const uint8_t *source = NULL;
        size_t destination_length = 0U;
        size_t source_length = 0U;
        WT_EXPECT_STATUS("the connection-ID reader reads its IDs", WT_OK,
                         wt_quic_long_header_connection_ids(
                             full_version_negotiation, sizeof(full_version_negotiation),
                             &destination, &destination_length, &source, &source_length));
        WT_EXPECT_INT("  the destination as the VN packet spells it", 4, (long)destination_length);
        WT_EXPECT_INT("  and the source", 4, (long)source_length);
      }
    }
  }

  /* The two guards `wt_quic_initial_token` applies before it reads anything: the header form and
   * the fixed bit together, then the packet type. AUD-0029: both were unexecuted, and both are
   * reachable from the server, which peeks the token of whatever a peer sends
   * (`runtime/server_retry.c`). A well-formed Initial sits behind each first byte, so the FIRST
   * BYTE IS THE MESSAGE'S ONLY FAULT -- with either guard deleted, the parse continues, succeeds,
   * and the test fails. */
  {
    static const uint8_t body[] = {0x00U, 0x00U, 0x00U, 0x01U, 0x04U, 0x01U, 0x02U, 0x03U,
                                   0x04U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x00U};
    static const struct {
      const char *label;
      uint8_t first;
    } cases[] = {
        {"a short header is not an Initial", 0x40U}, /* the long header bit is clear */
        {"a long header without the fixed bit is refused", 0x80U},
        {"a Handshake long header is not an Initial", 0xe0U}, /* type bits 10 */
    };
    uint8_t message[sizeof(body) + 1U];
    const uint8_t *token = NULL;
    size_t token_length = 0U;
    size_t i;

    /* The unmodified first byte parses, so each refusal below is about the byte and not the body. */
    message[0] = 0xc0U;
    memcpy(message + 1U, body, sizeof(body));
    WT_EXPECT_OK("a well-formed Initial is accepted for the guard checks",
                 wt_quic_initial_token(message, sizeof(message), &token, &token_length));
    for (i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
      message[0] = cases[i].first;
      WT_EXPECT_STATUS(cases[i].label, WT_ERR_PROTOCOL,
                       wt_quic_initial_token(message, sizeof(message), &token, &token_length));
    }
  }

  /* A handshake packet with a 2-byte packet number, a token of zero length and
   * a source connection ID, encoded and decoded. */
  {
    static const uint8_t dcid[4] = {1U, 2U, 3U, 4U};
    static const uint8_t scid[2] = {5U, 6U};
    static const uint8_t payload[8] = {0xAAU, 0xBBU, 0xCCU, 0xDDU, 0x11U, 0x22U, 0x33U, 0x44U};
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_quic_long_header_t decoded;
    status = wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1, dcid,
                                        sizeof(dcid), scid, sizeof(scid), NULL, 0U, 0x1234U, 2U,
                                        payload, sizeof(payload));
    WT_EXPECT_STATUS("a handshake packet encodes", WT_OK, status);
    WT_EXPECT_U64("to a byte more than its header and payload",
                  1U + 4U + 1U + 4U + 1U + 2U + 1U + 2U + 8U, (uint64_t)wt_writer_offset(&w));
    c = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_STATUS("and decodes", WT_OK, wt_quic_long_header_decode(&c, &decoded, &error));
    WT_EXPECT_U64("with the packet number reconstructed from two bytes", 0x1234U,
                  decoded.packet_number);
    WT_EXPECT_BYTES("and its payload", payload, decoded.payload, sizeof(payload));
    WT_EXPECT_U64("the destination connection ID survives", sizeof(dcid),
                  (uint64_t)decoded.destination_connection_id_len);
    WT_EXPECT_U64("and the source", sizeof(scid), (uint64_t)decoded.source_connection_id_len);
  }

  /* An Initial packet carries a token, and the token's length is a varint. */
  {
    static const uint8_t dcid[8] = {9U, 9U, 9U, 9U, 9U, 9U, 9U, 9U};
    static const uint8_t token[300] = {0};
    static const uint8_t payload[4] = {1U, 2U, 3U, 4U};
    wt_writer_t w = wt_writer_init(buffer, 512U);
    wt_quic_long_header_t decoded;
    status = wt_quic_long_header_encode(&w, WT_QUIC_PACKET_INITIAL, WT_QUIC_VERSION_1, dcid,
                                        sizeof(dcid), NULL, 0U, token, sizeof(token), 1U, 1U,
                                        payload, sizeof(payload));
    WT_EXPECT_STATUS("an Initial with a 300-byte token encodes", WT_OK, status);
    c = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_STATUS("and decodes", WT_OK, wt_quic_long_header_decode(&c, &decoded, &error));
    WT_EXPECT_U64("with the token length", sizeof(token), (uint64_t)decoded.token_len);
    /* The token view points into the packet: one byte of first byte, four of
     * version, a one-byte destination connection ID length and eight of ID, a
     * one-byte source connection ID length, and the token's own two-byte varint
     * length, which is where the token starts. */
    WT_EXPECT_TRUE("the token view points inside the packet",
                   decoded.token >= buffer && decoded.token < buffer + wt_writer_offset(&w));
    WT_EXPECT_U64("at the offset the header implies", 1U + 4U + 1U + 8U + 1U + 2U,
                  (uint64_t)(decoded.token - buffer));
  }

  /* A short header. Its connection ID length is the caller's, because the wire
   * does not carry it. */
  {
    static const uint8_t dcid[8] = {1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U};
    static const uint8_t payload[6] = {7U, 7U, 7U, 7U, 7U, 7U};
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_quic_short_header_t decoded;
    status = wt_quic_short_header_encode(&w, dcid, sizeof(dcid), 0xABCDU, 2U, 1, 0, payload,
                                         sizeof(payload));
    WT_EXPECT_STATUS("a short header encodes", WT_OK, status);
    WT_EXPECT_TRUE("with the fixed bit set", (buffer[0] & WT_QUIC_FIXED_BIT) != 0U);
    WT_EXPECT_TRUE("and the long header bit clear", (buffer[0] & WT_QUIC_LONG_HEADER_BIT) == 0U);
    WT_EXPECT_TRUE("and the key phase set", (buffer[0] & WT_QUIC_KEY_PHASE_BIT) != 0U);
    WT_EXPECT_TRUE("and the spin bit clear", (buffer[0] & WT_QUIC_SPIN_BIT) == 0U);
    c = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_STATUS("and decodes", WT_OK,
                     wt_quic_short_header_decode(&c, sizeof(dcid), &decoded, &error));
    WT_EXPECT_U64("with its packet number", 0xABCDU, decoded.packet_number);
    WT_EXPECT_INT("its key phase", 1, decoded.key_phase);
    WT_EXPECT_INT("its spin bit", 0, decoded.spin);
    WT_EXPECT_BYTES("its connection ID", dcid, decoded.destination_connection_id, sizeof(dcid));
    WT_EXPECT_BYTES("and a payload that runs to the end", payload, decoded.payload,
                    sizeof(payload));
  }

  /* A Retry packet: no packet number, a token, and the integrity tag last. */
  {
    static const uint8_t dcid[8] = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
    static const uint8_t scid[4] = {9U, 9U, 9U, 9U};
    static const uint8_t token[8] = {0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U, 0xA7U, 0xA8U};
    static const uint8_t tag[16] = {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
                                    0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U};
    uint8_t retry[64];
    wt_quic_retry_packet_t decoded;
    wt_writer_t w = wt_writer_init(retry, sizeof(retry));
    status = wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, dcid, sizeof(dcid), scid,
                                         sizeof(scid), token, sizeof(token), tag);
    WT_EXPECT_STATUS("a Retry encodes", WT_OK, status);
    WT_EXPECT_U64("to 1 + 4 + 9 + 5 + 8 + 16 bytes",
                  1U + 4U + 1U + (uint64_t)sizeof(dcid) + 1U + (uint64_t)sizeof(scid) +
                      (uint64_t)sizeof(token) + 16U,
                  (uint64_t)wt_writer_offset(&w));
    WT_EXPECT_STATUS("and decodes", WT_OK,
                     wt_quic_retry_packet_decode(retry, wt_writer_offset(&w), &decoded, &error));
    WT_EXPECT_U64("with its token length", sizeof(token), (uint64_t)decoded.token_len);
    WT_EXPECT_BYTES("its token", token, decoded.token, sizeof(token));
    WT_EXPECT_BYTES("and its integrity tag", tag, decoded.integrity_tag, 16U);
    WT_EXPECT_U64("and its version", WT_QUIC_VERSION_1, decoded.version);
    /* A Retry shorter than a header and a tag is refused. Shortening one by the
     * tag's length is not that case: the last sixteen bytes are always the tag,
     * so the decoder would read the token's tail as one -- which is why the
     * check is on the minimum length and not on where the tag starts. */
    WT_EXPECT_STATUS("a Retry below the minimum length is truncated", WT_ERR_TRUNCATED,
                     wt_quic_retry_packet_decode(retry, 20U, &decoded, &error));
    /* A Retry of exactly the minimum: ZERO-length connection IDs and a three-byte token, which is 26 bytes.
     *
     * The first version of this case decoded a 26-byte PREFIX of the packet built above, whose header names an
     * 8-byte destination and a 4-byte source ID -- so the "minimum" it claimed to test was really a header that
     * ran past the tag, and it passed only because the token length UNDERFLOWED to nearly `SIZE_MAX`. An audit
     * found the underflow and this case with it: a test that passes for the wrong reason is the thing that hides
     * the defect beside it. So the minimum is now BUILT, the prefix is asserted to be REFUSED, and the underflow
     * has the regression test it did not have. */
    {
      static const uint8_t short_token[3] = {0xA1U, 0xA2U, 0xA3U};
      static const uint8_t short_scid[1] = {0x77U};
      uint8_t minimal[64];
      wt_writer_t minimal_writer = wt_writer_init(minimal, sizeof(minimal));
      wt_quic_retry_packet_t minimal_decoded;

      /* The shortest Retry that can exist: no destination connection ID, the one-byte source ID a server that
       * retries must have chosen (RFC 9000 section 17.2.5), and a three-byte token. */
      WT_EXPECT_STATUS("a Retry with the shortest header encodes", WT_OK,
                       wt_quic_retry_packet_encode(&minimal_writer, WT_QUIC_VERSION_1, NULL, 0U,
                                                   short_scid, sizeof(short_scid), short_token,
                                                   sizeof(short_token), tag));
      WT_EXPECT_U64("to exactly the minimum length",
                    (uint64_t)(1U + 4U + 1U + 0U + 1U + 1U + 3U + 16U),
                    (uint64_t)wt_writer_offset(&minimal_writer));
      WT_EXPECT_STATUS("and that minimum parses", WT_OK,
                       wt_quic_retry_packet_decode(minimal, wt_writer_offset(&minimal_writer),
                                                   &minimal_decoded, &error));
      WT_EXPECT_U64("with its short token", (uint64_t)sizeof(short_token),
                    (uint64_t)minimal_decoded.token_len);
      WT_EXPECT_BYTES("byte for byte", short_token, minimal_decoded.token, sizeof(short_token));
      WT_EXPECT_BYTES("and its tag", tag, minimal_decoded.integrity_tag, 16U);

      /* A header that reaches into the tag is TRUNCATED, not a token of nearly `SIZE_MAX` bytes: this is the
       * exact packet the audit used, and before the guard it returned WT_OK with a token view past the end. */
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

  /* The refusals. */
  {
    /* The fixed bit cleared: RFC 9000 section 17.2 says such a packet is not
     * valid in this version and must be discarded. */
    static const uint8_t no_fixed[32] = {0x80U, 0x00U, 0x00U, 0x00U, 0x01U};
    static const uint8_t short_no_fixed[16] = {0x00U, 1U, 2U, 3U, 4U};
    static const uint8_t reserved[32] = {0xccU, 0x00U, 0x00U, 0x00U, 0x01U};
    static const uint8_t bad_cid[32] = {0xc0U, 0x00U, 0x00U, 0x00U, 0x01U, 0x15U};
    wt_quic_long_header_t long_header;
    wt_quic_short_header_t short_header;

    error = 0U;
    c = wt_cursor_init(no_fixed, sizeof(no_fixed));
    WT_EXPECT_STATUS("a long header without the fixed bit is refused", WT_ERR_PROTOCOL,
                     wt_quic_long_header_decode(&c, &long_header, &error));
    WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);

    error = 0U;
    c = wt_cursor_init(short_no_fixed, sizeof(short_no_fixed));
    WT_EXPECT_STATUS("a short header without the fixed bit is refused", WT_ERR_PROTOCOL,
                     wt_quic_short_header_decode(&c, 8U, &short_header, &error));

    /* Reserved bits are REPORTED, not refused (WT-167). RFC 9000 section 17.2 makes them a violation "after
     * removing both packet and header protection", and they are inside the AEAD's associated data -- so a
     * value that is non-zero after header unprotection may be a packet protected with another key set, which
     * RFC 9001 section 5.3 says to DISCARD. The decoder reports; `wt_quic_packet_read` refuses once the packet
     * has authenticated, which is what `test_quic_packet_io` asserts. Refusing here turned every packet from
     * another key epoch into a violation against the peer, which is what a Retry produced against quiche. */
    error = 0U;
    c = wt_cursor_init(reserved, sizeof(reserved));
    WT_EXPECT_STATUS("a long header with reserved bits set is not refused FOR them",
                     WT_ERR_PROTOCOL, wt_quic_long_header_decode(&c, &long_header, &error));
    WT_EXPECT_U64("  but for the Length field this buffer also gets wrong",
                  WT_QUIC_FRAME_ENCODING_ERROR, error);
    WT_EXPECT_INT("with the reserved bits reported on the way", 1, long_header.reserved_bits_set);

    /* And a WELL-FORMED header whose reserved bits are set parses, reporting them: the violation is the
     * caller's to make once the packet has authenticated (WT-167). */
    {
      static const uint8_t reserved_ok[17] = {
          0xccU, 0x00U, 0x00U, 0x00U, 0x01U, /* Initial, one-byte packet number, reserved bits set */
          0x00U,                             /* a zero-length Destination Connection ID */
          0x00U,                             /* and a zero-length Source Connection ID */
          0x00U,                             /* no token */
          0x08U, /* Length: one packet number byte and seven of payload */
          0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
      error = 0U;
      c = wt_cursor_init(reserved_ok, sizeof(reserved_ok));
      WT_EXPECT_STATUS("a well-formed header with reserved bits set parses", WT_OK,
                       wt_quic_long_header_decode(&c, &long_header, &error));
      WT_EXPECT_INT("reporting them", 1, long_header.reserved_bits_set);
      WT_EXPECT_U64("and its Length", 8U, (uint64_t)long_header.payload_len + 1U);
    }

    error = 0U;
    c = wt_cursor_init(bad_cid, sizeof(bad_cid));
    WT_EXPECT_STATUS("a 21-byte connection ID is refused", WT_ERR_PROTOCOL,
                     wt_quic_long_header_decode(&c, &long_header, &error));
    WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);

    /* Zero bytes of packet, and a packet truncated in the middle of every
     * field. */
    c = wt_cursor_init(NULL, 0U);
    WT_EXPECT_STATUS("an empty buffer is truncated", WT_ERR_TRUNCATED,
                     wt_quic_long_header_decode(&c, &long_header, &error));
    {
      /* A well-formed Initial header except that the Length claims more than
       * the buffer holds. */
      static const uint8_t short_payload[22] = {
          0xc3U, 0x00U, 0x00U, 0x00U, 0x01U, 0x08U, 0x83U, 0x94U, 0xc8U, 0xf0U, 0x3eU,
          0x51U, 0x57U, 0x08U, 0x00U, 0x00U, 0x44U, 0x9eU, 0x00U, 0x00U, 0x00U, 0x02U};
      c = wt_cursor_init(short_payload, sizeof(short_payload));
      WT_EXPECT_STATUS("a Length larger than the buffer is truncated", WT_ERR_TRUNCATED,
                       wt_quic_long_header_decode(&c, &long_header, &error));
    }
    /* Every prefix of a valid packet, which is the truncation corpus. The
     * packet is one byte of first byte, four of version, an eight-byte
     * destination connection ID, an empty source connection ID, a one-byte
     * Length of 8, a one-byte packet number and seven bytes of payload: 24
     * bytes, each of whose prefixes must be refused.
     *
     * The first byte is 0xe0: a Handshake packet (type 2) with a one-byte packet
     * number. An Initial would carry a token length field, which this vector
     * does not have -- and the first version of it did not, so the parser read
     * the Length as a token length and then ran out of packet. */
    {
      static const uint8_t complete[24] = {0xe0U, 0x00U, 0x00U, 0x00U, 0x01U, 0x08U, 0x01U, 0x02U,
                                           0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x00U, 0x08U,
                                           0x01U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U};
      size_t cut;
      for (cut = 0U; cut < sizeof(complete); cut++) {
        c = wt_cursor_init(complete, cut);
        WT_EXPECT_STATUS("a prefix of a packet is truncated", WT_ERR_TRUNCATED,
                         wt_quic_long_header_decode(&c, &long_header, &error));
      }
      /* And the whole thing parses, so the corpus above is not refusing
       * everything. */
      c = wt_cursor_init(complete, sizeof(complete));
      WT_EXPECT_STATUS("the complete packet parses", WT_OK,
                       wt_quic_long_header_decode(&c, &long_header, &error));
      WT_EXPECT_U64("with its packet number", 1U, long_header.packet_number);
      WT_EXPECT_U64("and its payload", 7U, (uint64_t)long_header.payload_len);
      WT_EXPECT_U64("and consumes the datagram", 24U, (uint64_t)long_header.total_len);
    }
  }

  /* Encoding refusals: the encoder will not build a packet the parser would
   * refuse, and it computes the Length so a caller cannot get it wrong. */
  {
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    static const uint8_t id[21] = {0};
    static const uint8_t token[4] = {0};
    static const uint8_t payload[4] = {0};
    WT_EXPECT_STATUS("a 21-byte connection ID cannot be encoded", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_long_header_encode(&w, WT_QUIC_PACKET_INITIAL, WT_QUIC_VERSION_1, id,
                                                21U, NULL, 0U, NULL, 0U, 1U, 1U, payload,
                                                sizeof(payload)));
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_STATUS("a token on a non-Initial packet is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1,
                                                NULL, 0U, NULL, 0U, token, sizeof(token), 1U, 1U,
                                                payload, sizeof(payload)));
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_STATUS("a Retry type is refused by the long header encoder", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_long_header_encode(&w, WT_QUIC_PACKET_RETRY, WT_QUIC_VERSION_1, NULL,
                                                0U, NULL, 0U, NULL, 0U, 1U, 1U, payload,
                                                sizeof(payload)));
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_STATUS("a five-byte packet number is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1,
                                                NULL, 0U, NULL, 0U, NULL, 0U, 1U, 5U, payload,
                                                sizeof(payload)));
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_STATUS(
        "a short header with no packet number is refused", WT_ERR_INVALID_ARGUMENT,
        wt_quic_short_header_encode(&w, NULL, 0U, 1U, 0U, 0, 0, payload, sizeof(payload)));
    WT_EXPECT_STATUS("a NULL writer is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_long_header_encode(NULL, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1,
                                                NULL, 0U, NULL, 0U, NULL, 0U, 1U, 1U, payload,
                                                sizeof(payload)));
    /* A Short header whose connection ID length is above twenty is a caller's
     * bug, since the length is the caller's own. */
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_STATUS(
        "a short header refuses an over-long connection ID", WT_ERR_INVALID_ARGUMENT,
        wt_quic_short_header_encode(&w, id, 21U, 1U, 1U, 0, 0, payload, sizeof(payload)));
    /* A Retry needs a source connection ID: it is the one the server chose. */
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_STATUS("a Retry without a source connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, NULL, 0U, NULL, 0U, NULL,
                                                 0U, (const uint8_t *)buffer));
    WT_EXPECT_STATUS(
        "a NULL writer is refused by the short encoder", WT_ERR_INVALID_ARGUMENT,
        wt_quic_short_header_encode(NULL, NULL, 0U, 1U, 1U, 0, 0, payload, sizeof(payload)));
    WT_EXPECT_STATUS("a NULL cursor is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_long_header_decode(NULL, NULL, &error));
  }

  /* A coalesced datagram: an Initial then a Handshake, walked by the reported
   * sizes. */
  {
    static const uint8_t payload_a[4] = {1U, 2U, 3U, 4U};
    static const uint8_t payload_b[3] = {5U, 6U, 7U};
    uint8_t datagram[256];
    wt_writer_t w = wt_writer_init(datagram, sizeof(datagram));
    wt_quic_long_header_t first;
    wt_quic_long_header_t second;
    size_t first_len;
    (void)wt_quic_long_header_encode(&w, WT_QUIC_PACKET_INITIAL, WT_QUIC_VERSION_1, NULL, 0U, NULL,
                                     0U, NULL, 0U, 1U, 1U, payload_a, sizeof(payload_a));
    first_len = wt_writer_offset(&w);
    (void)wt_quic_long_header_encode(&w, WT_QUIC_PACKET_HANDSHAKE, WT_QUIC_VERSION_1, NULL, 0U,
                                     NULL, 0U, NULL, 0U, 1U, 1U, payload_b, sizeof(payload_b));
    c = wt_cursor_init(datagram, wt_writer_offset(&w));
    WT_EXPECT_STATUS("the first coalesced packet parses", WT_OK,
                     wt_quic_long_header_decode(&c, &first, &error));
    WT_EXPECT_INT("it is the Initial", (long)WT_QUIC_PACKET_INITIAL, (long)first.type);
    WT_EXPECT_U64("and its size is where the next one starts", (uint64_t)first_len,
                  (uint64_t)first.total_len);
    WT_EXPECT_STATUS("the second parses where the first ended", WT_OK,
                     wt_quic_long_header_decode(&c, &second, &error));
    WT_EXPECT_INT("it is the Handshake", (long)WT_QUIC_PACKET_HANDSHAKE, (long)second.type);
    WT_EXPECT_BYTES("with its own payload", payload_b, second.payload, sizeof(payload_b));
    WT_EXPECT_INT("and the datagram is consumed", 1, wt_cursor_at_end(&c));
  }

  /* Names. */
  WT_EXPECT_STR("initial", "initial", wt_quic_packet_type_name(WT_QUIC_PACKET_INITIAL));
  WT_EXPECT_STR("0-rtt", "0-rtt", wt_quic_packet_type_name(WT_QUIC_PACKET_ZERO_RTT));
  WT_EXPECT_STR("handshake", "handshake", wt_quic_packet_type_name(WT_QUIC_PACKET_HANDSHAKE));
  WT_EXPECT_STR("retry", "retry", wt_quic_packet_type_name(WT_QUIC_PACKET_RETRY));
  WT_EXPECT_STR("unknown", "unknown", wt_quic_packet_type_name((wt_quic_packet_type_t)9));

  test_a_zero_length_destination_connection_id();
  test_the_connection_ids_of_a_long_header_can_be_read_from_a_prefix();
  test_a_retry_ignores_the_unused_bits();
  test_a_retry_encoder_refuses_missing_argument_bytes();
  WT_TEST_MAIN_END("wt_quic_packet");
}
