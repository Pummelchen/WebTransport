/* QPACK's field section prefix (RFC 9204 section 4.5.1).
 *
 * The Required Insert Count is sent modulo twice the table's size in entries, so a
 * round trip alone would not say the wrapping is right -- it would agree with
 * itself. The tests therefore exercise the wrap directly (a count larger than the
 * full range must decode back to itself after wrapping), the two error exits the
 * section names, and the Base's signed delta, whose negative form has one
 * subtracted and so can be asked for something impossible. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static void expect_round_trip(uint64_t required, uint64_t base, uint64_t max_entries) {
  uint8_t bytes[24];
  wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
  wt_cursor_t c;
  wt_qpack_header_prefix_t prefix;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  /* The decoder knows the insertions the encoder has made, which is what bounds
   * the wrapped value: here it knows exactly what was referenced. */
  WT_EXPECT_OK("a prefix encodes", wt_qpack_header_prefix_encode(&w, required, base, max_entries));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes",
               wt_qpack_header_prefix_decode(&c, max_entries, required, &prefix, &error));
  WT_EXPECT_U64("to the required insert count", required, prefix.required_insert_count);
  WT_EXPECT_U64("and the base", base, prefix.base);
  WT_EXPECT_TRUE("leaving nothing behind", wt_cursor_at_end(&c));
}

static void test_round_trips_and_wrapping(void) {
  /* No dynamic references: both values zero, which is the common case. */
  expect_round_trip(0U, 0U, 128U);

  /* Small values inside the range. */
  expect_round_trip(1U, 0U, 128U);
  expect_round_trip(8U, 8U, 128U);
  expect_round_trip(8U, 4U, 128U);

  /* MaxEntries of eight means a full range of sixteen, so a count of twenty
   * WRAPS: the encoder sends (20 % 16) + 1 = 5, and the decoder must reconstruct
   * twenty from the window it knows. */
  expect_round_trip(20U, 20U, 8U);
  expect_round_trip(19U, 3U, 8U);
  expect_round_trip(1024U, 1000U, 8U);

  /* And the encode of a reference with no table at all is refused rather than
   * written against nothing. */
  {
    uint8_t bytes[8];
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_STATUS("a reference with MaxEntries zero is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_qpack_header_prefix_encode(&w, 1U, 0U, 0U));
  }
}

static void test_errors(void) {
  uint8_t bytes[8];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_header_prefix_t prefix;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  /* A prefix whose encoded count cannot be a wrapped value: with MaxEntries of
   * one the full range is two, so an encoded count above two is not one. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an impossible encoded count writes", wt_qpack_integer_encode(&w, 8U, 0U, 5U));
  WT_EXPECT_OK("followed by a base", wt_qpack_integer_encode(&w, 7U, 0U, 0U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("and decoding it is refused", WT_ERR_PROTOCOL,
                   wt_qpack_header_prefix_decode(&c, 1U, 4U, &prefix, &error));
  WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED, (uint64_t)error);

  /* A required count beyond what the decoder knows plus the window: the encoder
   * cannot have inserted that many. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a too-large count writes", wt_qpack_integer_encode(&w, 8U, 0U, 16U));
  WT_EXPECT_OK("with its base", wt_qpack_integer_encode(&w, 7U, 0U, 0U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("which the decoder refuses", WT_ERR_PROTOCOL,
                   wt_qpack_header_prefix_decode(&c, 8U, 0U, &prefix, &error));
  WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED, (uint64_t)error);

  /* A negative delta larger than the required count: Base = required - delta - 1
   * would go below zero, which no encoder can mean. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a required count of one writes", wt_qpack_integer_encode(&w, 8U, 0U, 2U));
  WT_EXPECT_OK("with a negative delta of five", wt_qpack_integer_encode(&w, 7U, 0x80U, 5U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("and decoding it is refused", WT_ERR_PROTOCOL,
                   wt_qpack_header_prefix_decode(&c, 8U, 1U, &prefix, &error));

  /* An incomplete prefix is not an error: the rest of the field section may still
   * arrive (section 2.2). */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a prefix with no base writes", wt_qpack_integer_encode(&w, 8U, 0U, 2U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("and is incomplete, not malformed", WT_ERR_TRUNCATED,
                   wt_qpack_header_prefix_decode(&c, 8U, 1U, &prefix, &error));
  WT_EXPECT_U64("with no error to send yet", (uint64_t)WT_QPACK_ERROR_NONE, (uint64_t)error);
}

/* AUD-0026. RFC 9204 section 4.5.1's decoding algorithm has six error exits and a wrap branch;
 * line coverage showed four of the exits and the wrap never executed, so a decoder that lost
 * them would still pass the suite. Each is aimed at one line of the algorithm rather than at
 * "something malformed". */
static void test_the_algorithm_s_refusals_are_all_reachable(void) {
  uint8_t bytes[24];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_header_prefix_t prefix;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  /* A MaxEntries whose doubled full range wraps: the guard is a comparison against MaxEntries,
   * because the multiplication itself cannot be trusted. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a prefix writes", wt_qpack_integer_encode(&w, 8U, 0U, 1U));
  WT_EXPECT_OK("with a base", wt_qpack_integer_encode(&w, 7U, 0U, 0U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  error = WT_QPACK_ERROR_NONE;
  WT_EXPECT_STATUS("a MaxEntries whose full range wraps is refused", WT_ERR_PROTOCOL,
                   wt_qpack_header_prefix_decode(&c, UINT64_MAX, 0U, &prefix, &error));
  WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED, (uint64_t)error);

  /* The encoded count is not a valid prefixed integer at all: its continuation runs past the
   * 62-bit bound, which the integer decoder reports as a protocol error rather than truncation. */
  {
    static const uint8_t not_an_integer[] = {0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
                                             0xffU, 0xffU, 0xffU, 0xffU, 0x7fU};
    c = wt_cursor_init(not_an_integer, sizeof(not_an_integer));
    error = WT_QPACK_ERROR_NONE;
    WT_EXPECT_STATUS("an encoded count that is not an integer is refused", WT_ERR_PROTOCOL,
                     wt_qpack_header_prefix_decode(&c, 8U, 1U, &prefix, &error));
    WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED,
                  (uint64_t)error);
  }

  /* The same for the delta, which is decoded after a valid encoded count. */
  {
    static const uint8_t good_then_bad[] = {0x01U, 0x80U, 0xffU, 0xffU, 0xffU, 0xffU,
                                            0xffU, 0xffU, 0xffU, 0xffU, 0x7fU};
    c = wt_cursor_init(good_then_bad, sizeof(good_then_bad));
    error = WT_QPACK_ERROR_NONE;
    WT_EXPECT_STATUS("a delta that is not an integer is refused", WT_ERR_PROTOCOL,
                     wt_qpack_header_prefix_decode(&c, 8U, 1U, &prefix, &error));
    WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED,
                  (uint64_t)error);
  }

  /* `required == 0` after the arithmetic is an error the algorithm names explicitly, even though
   * an encoded count of zero is the legal way to say "nothing required". */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an encoded count of one writes", wt_qpack_integer_encode(&w, 8U, 0U, 1U));
  WT_EXPECT_OK("with a base", wt_qpack_integer_encode(&w, 7U, 0U, 0U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  error = WT_QPACK_ERROR_NONE;
  WT_EXPECT_STATUS("a wrap that lands on zero is refused", WT_ERR_PROTOCOL,
                   wt_qpack_header_prefix_decode(&c, 1U, 0U, &prefix, &error));
  WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED, (uint64_t)error);

  /* And the WRAP itself, which is not an error: a required count past the window comes back
   * inside it. Six inserts known, a window of two, so the full range is four and an encoded two
   * names nine, which subtracts to five. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an encoded count of two writes", wt_qpack_integer_encode(&w, 8U, 0U, 2U));
  WT_EXPECT_OK("with a base", wt_qpack_integer_encode(&w, 7U, 0U, 0U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("a wrapped required count decodes",
               wt_qpack_header_prefix_decode(&c, 2U, 6U, &prefix, &error));
  WT_EXPECT_U64("wrapped into the window", 5U, prefix.required_insert_count);
  WT_EXPECT_U64("with the base above it", 5U, prefix.base);

  /* A positive delta that would carry the base past UINT64_MAX is refused rather than wrapped:
   * the decoder's own count is the caller's, so this is reachable with a large one. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an encoded count of one writes", wt_qpack_integer_encode(&w, 8U, 0U, 1U));
  WT_EXPECT_OK("with a positive delta of ten", wt_qpack_integer_encode(&w, 7U, 0x00U, 10U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  error = WT_QPACK_ERROR_NONE;
  WT_EXPECT_STATUS("a base that would overflow is refused", WT_ERR_PROTOCOL,
                   wt_qpack_header_prefix_decode(&c, 1U, UINT64_MAX - 10U, &prefix, &error));
  WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED, (uint64_t)error);
}

int main(void) {
  test_round_trips_and_wrapping();
  test_errors();
  test_the_algorithm_s_refusals_are_all_reachable();
  WT_TEST_MAIN_END("wt_qpack_header_prefix");
}
