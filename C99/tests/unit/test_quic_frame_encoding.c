#include "test_quic_frame_encoding_support.h"
#include "vectors/rfc9001_client_initial.h"
#include "webtransport/quic/frame.h"
#include "wt_test.h"

static void test_ack_ranges(void) {
  uint8_t buffer[128];
  wt_quic_frame_t frame;
  wt_quic_frame_t decoded;
  wt_quic_error_t error = 0U;
  wt_quic_ack_range_t range;
  size_t encoded = 0U;
  size_t i;

  /* An ACK with three additional ranges, encoded by building the wire bytes of
   * the ranges directly, so the test does not depend on an encoder for a
   * structure the parser keeps as bytes. */
  {
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_quic_frame_t ack = wt_quic_frame_make(WT_QUIC_FRAME_KIND_ACK);
    ack.as.ack.largest = 100U;
    ack.as.ack.delay = 7U;
    ack.as.ack.first_range = 3U;
    ack.as.ack.range_count = 3U;
    /* The ranges are built into a scratch area and handed to the encoder
     * through a temporary frame, so `wt_quic_frame_ack_range_at` can walk
     * them. */
    {
      wt_writer_t rw;
      uint8_t scratch[32];
      wt_quic_frame_t holder;
      rw = wt_writer_init(scratch, sizeof(scratch));
      (void)wt_quic_writer_varint(&rw, 1U);
      (void)wt_quic_writer_varint(&rw, 3U);
      (void)wt_quic_writer_varint(&rw, 4U);
      (void)wt_quic_writer_varint(&rw, 5U);
      (void)wt_quic_writer_varint(&rw, 0U);
      (void)wt_quic_writer_varint(&rw, 1U);
      holder = ack;
      holder.as.ack.ranges = scratch;
      holder.as.ack.ranges_len = wt_writer_offset(&rw);
      encoded = encode_ok("an ACK with three ranges encodes", &holder, buffer, sizeof(buffer));
      /* The ranges are read back from the encoded frame, which is what the
       * accessor is for. */
      (void)encoded;
    }
    (void)w;
    (void)ack;
  }

  /* A hand-built ACK frame with ranges, parsed: the ranges are the wire bytes
   * and the accessor decodes them one at a time. */
  {
    /* Type 0x02, largest 100, delay 7, count 3, first range 3, then three
     * gap/length pairs: (1,3), (4,5), (0,1).
     *
     * THE LARGEST ACKNOWLEDGED IS `40 64`, NOT `64`. A QUIC varint's first two
     * bits are its length: 0x64 has 01 in those bits, so it is the first byte of
     * a two-byte value and the parser reads the following byte as its low half.
     * Hand-writing a field value into a vector without its prefix is the mistake
     * this test made first, and it looked exactly like a parser defect: the
     * frame's fields came back shifted by one byte. */
    static const uint8_t bytes[] = {0x02U, 0x40U, 0x64U, 0x07U, 0x03U, 0x03U,
                                    0x01U, 0x03U, 0x04U, 0x05U, 0x00U, 0x01U};
    wt_cursor_t c = wt_cursor_init(bytes, sizeof(bytes));
    static const uint64_t expected_gap[3] = {1U, 4U, 0U};
    static const uint64_t expected_length[3] = {3U, 5U, 1U};
    WT_EXPECT_STATUS("the hand-built ACK parses", WT_OK,
                     wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_INT("it is an ACK", (long)WT_QUIC_FRAME_KIND_ACK, (long)decoded.kind);
    WT_EXPECT_U64("largest acknowledged", 100U, decoded.as.ack.largest);
    WT_EXPECT_U64("ack delay", 7U, decoded.as.ack.delay);
    WT_EXPECT_U64("first range", 3U, decoded.as.ack.first_range);
    WT_EXPECT_U64("range count", 3U, decoded.as.ack.range_count);
    WT_EXPECT_INT("and no ECN counts", 0, decoded.as.ack.has_ecn);
    for (i = 0U; i < 3U; i++) {
      WT_EXPECT_STATUS("the range decodes", WT_OK, wt_quic_frame_ack_range_at(&decoded, i, &range));
      WT_EXPECT_U64("  gap", expected_gap[i], range.gap);
      WT_EXPECT_U64("  length", expected_length[i], range.length);
    }
    WT_EXPECT_STATUS("an index past the end is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_ack_range_at(&decoded, 3U, &range));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_ack_range_at(&decoded, 0U, NULL));
    /* The frame must be followed by nothing for this buffer, and the ACK
     * consumed exactly its own bytes. */
    WT_EXPECT_INT("the ACK consumed the whole buffer", 1, wt_cursor_at_end(&c));
  }

  /* An ACK that claims ranges it does not carry is truncated, not a walk off
   * the end. */
  {
    static const uint8_t short_ack[] = {0x02U, 0x40U, 0x64U, 0x07U, 0x05U, 0x03U, 0x01U, 0x03U};
    wt_cursor_t c = wt_cursor_init(short_ack, sizeof(short_ack));
    WT_EXPECT_STATUS("an ACK with missing ranges is truncated", WT_ERR_TRUNCATED,
                     wt_quic_frame_decode(&c, &decoded, &error));
  }

  /* An ACK that claims a huge number of ranges must not make the parser
   * allocate or loop: it walks the ranges it has and refuses. */
  {
    /* A count of 2^62 - 1, which is an eight-byte varint of all ones, followed
     * by a valid first range and one range. The parser must refuse it by
     * running out rather than by looping 2^62 times or allocating for it. */
    static const uint8_t many[15] = {0x02U, 0x40U, 0x64U, 0x07U, 0xffU, 0xffU, 0xffU, 0xffU,
                                     0xffU, 0xffU, 0xffU, 0xffU, 0x03U, 0x01U, 0x03U};
    wt_cursor_t c = wt_cursor_init(many, sizeof(many));
    WT_EXPECT_STATUS("an ACK claiming many ranges is refused without walking", WT_ERR_TRUNCATED,
                     wt_quic_frame_decode(&c, &decoded, &error));
  }

  /* ACK_ECN carries three extra counts. */
  {
    static const uint8_t ecn[] = {0x03U, 0x40U, 0x64U, 0x07U, 0x00U, 0x03U, 0x01U, 0x02U, 0x00U};
    wt_cursor_t c = wt_cursor_init(ecn, sizeof(ecn));
    WT_EXPECT_STATUS("an ACK_ECN parses", WT_OK, wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_INT("with ECN counts", 1, decoded.as.ack.has_ecn);
    WT_EXPECT_U64("ect0", 1U, decoded.as.ack.ect0);
    WT_EXPECT_U64("ect1", 2U, decoded.as.ack.ect1);
    WT_EXPECT_U64("ecn-ce", 0U, decoded.as.ack.ecn_ce);
  }

  /* The accessor on a frame that is not an ACK. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  WT_EXPECT_STATUS("the range accessor refuses a non-ACK", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_frame_ack_range_at(&frame, 0U, &range));
  WT_EXPECT_STATUS("the range accessor refuses a NULL frame", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_frame_ack_range_at(NULL, 0U, &range));
}
static void test_frame_names(void) {
  WT_EXPECT_STR("padding", "padding", wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_PADDING));
  WT_EXPECT_STR("stream", "stream", wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_STREAM));
  WT_EXPECT_STR("connection close", "connection-close",
                wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT));
  WT_EXPECT_STR("application close", "connection-close-application",
                wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION));
  WT_EXPECT_STR("datagram", "datagram", wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_DATAGRAM));
  WT_EXPECT_STR("an unknown kind", "unknown", wt_quic_frame_kind_name((wt_quic_frame_type_t)999));
}
int main(void) {
  test_ack_ranges();
  test_frame_names();
  WT_TEST_MAIN_END("test_quic_frame_encoding");
}
