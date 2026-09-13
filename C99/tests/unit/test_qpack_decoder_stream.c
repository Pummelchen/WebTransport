/* QPACK's decoder stream instructions (RFC 9204 section 4.4).
 *
 * These three instructions are how a decoder tells an encoder what it may evict, so
 * the tests are about what a decoder may NOT do: confirm zero insertions, confirm
 * more insertions than were made, or send an instruction that is not one. The
 * counters are checked because they are what the encoder-side eviction logic will
 * read, and the wire bytes are written by this implementation's own writers so the
 * two sides are checked against each other. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static void test_the_three_instructions(void) {
  wt_qpack_decoder_stream_t stream;
  uint8_t bytes[16];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  wt_qpack_decoder_stream_init(&stream);
  WT_EXPECT_U64("nothing is acknowledged to start", 0U, stream.acknowledged_insert_count);

  /* 1 SectionID(7+): distinct from the other two by its top bit. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a section acknowledgement writes",
               wt_qpack_decoder_stream_write_section_acknowledgement(&w, 4U));
  WT_EXPECT_U64("with the 1 pattern", 0x84U, (uint64_t)bytes[0]);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and applies", wt_qpack_decoder_stream_apply(&stream, NULL, &c, &error));
  WT_EXPECT_U64("counting one section", 1U, stream.sections_acknowledged);
  WT_EXPECT_TRUE("leaving nothing behind", wt_cursor_at_end(&c));

  /* 01 StreamID(6+). */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a cancellation writes", wt_qpack_decoder_stream_write_stream_cancellation(&w, 3U));
  WT_EXPECT_U64("with the 01 pattern", 0x43U, (uint64_t)bytes[0]);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and applies", wt_qpack_decoder_stream_apply(&stream, NULL, &c, &error));
  WT_EXPECT_U64("counting one cancelled stream", 1U, stream.streams_cancelled);

  /* 00 Increment(6+). */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an increment writes", wt_qpack_decoder_stream_write_insert_count_increment(&w, 5U));
  WT_EXPECT_U64("with the 00 pattern", 0x05U, (uint64_t)bytes[0]);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and applies", wt_qpack_decoder_stream_apply(&stream, NULL, &c, &error));
  WT_EXPECT_U64("adding to the acknowledged count", 5U, stream.acknowledged_insert_count);

  /* A second increment accumulates. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("another increment writes",
               wt_qpack_decoder_stream_write_insert_count_increment(&w, 2U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and applies", wt_qpack_decoder_stream_apply(&stream, NULL, &c, &error));
  WT_EXPECT_U64("to seven", 7U, stream.acknowledged_insert_count);
}

static void test_what_a_decoder_may_not_say(void) {
  wt_qpack_decoder_stream_t stream;
  wt_qpack_dynamic_table_t table;
  uint8_t bytes[16];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;
  uint64_t index = 0U;

  wt_qpack_decoder_stream_init(&stream);
  wt_qpack_dynamic_init(&table, 4096U);
  WT_EXPECT_OK("the table has two entries",
               wt_qpack_dynamic_insert(&table, (const uint8_t *)"a", 1U, (const uint8_t *)"1", 1U,
                                       &index));
  WT_EXPECT_OK("and the second",
               wt_qpack_dynamic_insert(&table, (const uint8_t *)"b", 1U, (const uint8_t *)"2", 1U,
                                       &index));

  /* Zero says nothing, and section 4.4.3 makes it an error rather than a no-op. */
  WT_EXPECT_STATUS("a zero increment cannot be written", WT_ERR_INVALID_ARGUMENT,
                   wt_qpack_decoder_stream_write_insert_count_increment(&w, 0U));
  {
    static const uint8_t zero_increment[1] = {0x00U};
    c = wt_cursor_init(zero_increment, sizeof(zero_increment));
    WT_EXPECT_STATUS("nor applied", WT_ERR_PROTOCOL,
                     wt_qpack_decoder_stream_apply(&stream, &table, &c, &error));
    WT_EXPECT_U64("as a decoder stream error", WT_QPACK_ERROR_DECODER_STREAM, (uint64_t)error);
  }

  /* More insertions than the table has: the decoder cannot have processed them. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an increment of three writes",
               wt_qpack_decoder_stream_write_insert_count_increment(&w, 3U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("but two insertions exist", WT_ERR_PROTOCOL,
                   wt_qpack_decoder_stream_apply(&stream, &table, &c, &error));
  WT_EXPECT_U64("so it is refused", WT_QPACK_ERROR_DECODER_STREAM, (uint64_t)error);
  WT_EXPECT_U64("with the count unchanged", 0U, stream.acknowledged_insert_count);

  /* Two is fine, and then a third is not. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an increment of two writes",
               wt_qpack_decoder_stream_write_insert_count_increment(&w, 2U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and applies", wt_qpack_decoder_stream_apply(&stream, &table, &c, &error));
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a further increment writes",
               wt_qpack_decoder_stream_write_insert_count_increment(&w, 1U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("but exceeds the insertions", WT_ERR_PROTOCOL,
                   wt_qpack_decoder_stream_apply(&stream, &table, &c, &error));

  /* A truncated instruction and an empty one. */
  {
    /* 0x7f is a Stream Cancellation whose six-bit prefix is full, so a
     * continuation byte must follow and does not: the instruction is truncated.
     * (0x80 would be a COMPLETE section acknowledgement of section zero -- the
     * prefix holds the whole value -- which is why that byte is not the vector.) */
    static const uint8_t truncated[1] = {0x7fU};
    c = wt_cursor_init(truncated, sizeof(truncated));
    WT_EXPECT_STATUS("a truncated stream cancellation is incomplete", WT_ERR_TRUNCATED,
                     wt_qpack_decoder_stream_apply(&stream, NULL, &c, &error));
    /* NOT a decoder stream error: the rest of the instruction may still arrive, and
     * only a malformed one is the peer's fault. The caller that sees the stream end
     * with an instruction half-read is the one that reports the error. */
    WT_EXPECT_U64("with no error to send yet", (uint64_t)WT_QPACK_ERROR_NONE, (uint64_t)error);
  }
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("an empty buffer is not an instruction", WT_ERR_TRUNCATED,
                   wt_qpack_decoder_stream_apply(&stream, NULL, &c, &error));
}

int main(void) {
  test_the_three_instructions();
  test_what_a_decoder_may_not_say();
  WT_TEST_MAIN_END("wt_qpack_decoder_stream");
}
