/* QPACK's encoder stream instructions (RFC 9204 section 4.3).
 *
 * The instructions are what fills the dynamic table, so the tests apply each one
 * and then read the TABLE, not the instruction: what matters is that the entry the
 * encoder described is the entry the decoder stored. Two errors are only visible at
 * this layer -- a capacity above the SETTINGS limit and an index naming an evicted
 * entry -- and both are QPACK_ENCODER_STREAM_ERROR. The instructions are written by
 * this implementation's own writers, so the round trip also says the two sides
 * agree on the wire format. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static void apply(wt_qpack_encoder_stream_t *stream, const uint8_t *bytes, size_t length,
                  const char *label) {
  wt_cursor_t c = wt_cursor_init(bytes, length);
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;
  WT_EXPECT_OK(label, wt_qpack_encoder_stream_apply(stream, &c, &error));
  WT_EXPECT_TRUE("leaving nothing behind", wt_cursor_at_end(&c));
}

static void test_capacity(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_encoder_stream_t stream;
  uint8_t bytes[16];
  wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
  wt_cursor_t c;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  wt_qpack_dynamic_init(&table, 4096U);
  wt_qpack_encoder_stream_init(&stream, &table, 4096U);

  WT_EXPECT_OK("a capacity instruction writes",
               wt_qpack_encoder_stream_write_capacity(&w, 512U));
  apply(&stream, bytes, wt_writer_offset(&w), "and applies");
  WT_EXPECT_U64("setting the table's capacity", 512U, (uint64_t)table.capacity);

  /* Above the limit this endpoint advertised: an error, not a clamp. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a larger capacity writes",
               wt_qpack_encoder_stream_write_capacity(&w, 8192U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("but applying it is refused", WT_ERR_PROTOCOL,
                   wt_qpack_encoder_stream_apply(&stream, &c, &error));
  WT_EXPECT_U64("as an encoder stream error", WT_QPACK_ERROR_ENCODER_STREAM, (uint64_t)error);
  WT_EXPECT_U64("with the capacity unchanged", 512U, (uint64_t)table.capacity);
}

static void test_insertions(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_encoder_stream_t stream;
  uint8_t bytes[64];
  wt_writer_t w;
  const uint8_t *name = NULL;
  const uint8_t *value = NULL;
  size_t name_length = 0U;
  size_t value_length = 0U;

  wt_qpack_dynamic_init(&table, 4096U);
  wt_qpack_encoder_stream_init(&stream, &table, 4096U);

  /* An insertion whose name is written out. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a literal insertion writes",
               wt_qpack_encoder_stream_write_insert_literal(&w, (const uint8_t *)"x-a", 3U,
                                                            (const uint8_t *)"one", 3U));
  apply(&stream, bytes, wt_writer_offset(&w), "and applies");
  WT_EXPECT_U64("storing one entry", 1U, (uint64_t)table.count);
  WT_EXPECT_OK("whose name reads back",
               wt_qpack_dynamic_entry(&table, 0U, &name, &name_length, &value, &value_length));
  WT_EXPECT_BYTES("as what was written", (const uint8_t *)"x-a", name, 3U);
  WT_EXPECT_BYTES("with its value", (const uint8_t *)"one", value, 3U);

  /* An insertion whose name comes from the STATIC table: entry 15 is :method. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a static-name insertion writes",
               wt_qpack_encoder_stream_write_insert_name_reference(
                   &w, 1, 15U, (const uint8_t *)"GET", 3U));
  apply(&stream, bytes, wt_writer_offset(&w), "and applies");
  WT_EXPECT_U64("storing a second entry", 2U, (uint64_t)table.count);
  WT_EXPECT_OK("whose name came from the table",
               wt_qpack_dynamic_entry(&table, 1U, &name, &name_length, &value, &value_length));
  WT_EXPECT_BYTES("as :method", (const uint8_t *)":method", name, 7U);
  WT_EXPECT_BYTES("with the new value", (const uint8_t *)"GET", value, 3U);

  /* And one whose name comes from the DYNAMIC table: relative 0 is the entry just
   * inserted, so this stores its name again with a different value. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a dynamic-name insertion writes",
               wt_qpack_encoder_stream_write_insert_name_reference(
                   &w, 0, 0U, (const uint8_t *)"POST", 4U));
  apply(&stream, bytes, wt_writer_offset(&w), "and applies");
  WT_EXPECT_U64("storing a third entry", 3U, (uint64_t)table.count);
  WT_EXPECT_OK("whose name is the referenced one",
               wt_qpack_dynamic_entry(&table, 2U, &name, &name_length, &value, &value_length));
  WT_EXPECT_BYTES(":method again", (const uint8_t *)":method", name, 7U);
  WT_EXPECT_BYTES("with its own value", (const uint8_t *)"POST", value, 4U);
}

static void test_duplicate_and_errors(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_encoder_stream_t stream;
  uint8_t bytes[32];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;
  const uint8_t *name = NULL;
  const uint8_t *value = NULL;
  size_t name_length = 0U;
  size_t value_length = 0U;

  wt_qpack_dynamic_init(&table, 4096U);
  wt_qpack_encoder_stream_init(&stream, &table, 4096U);
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an entry writes",
               wt_qpack_encoder_stream_write_insert_literal(&w, (const uint8_t *)"n", 1U,
                                                            (const uint8_t *)"v", 1U));
  apply(&stream, bytes, wt_writer_offset(&w), "and inserts");

  /* Duplicating relative 0 copies the newest entry to the end. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a duplicate writes", wt_qpack_encoder_stream_write_duplicate(&w, 0U));
  apply(&stream, bytes, wt_writer_offset(&w), "and applies");
  WT_EXPECT_U64("giving two entries", 2U, (uint64_t)table.count);
  WT_EXPECT_OK("the copy reads back",
               wt_qpack_dynamic_entry(&table, 1U, &name, &name_length, &value, &value_length));
  WT_EXPECT_BYTES("with the same name", (const uint8_t *)"n", name, 1U);
  WT_EXPECT_BYTES("and the same value", (const uint8_t *)"v", value, 1U);

  /* An index that was never inserted. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an out-of-range duplicate writes", wt_qpack_encoder_stream_write_duplicate(&w, 9U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_STATUS("but applying it is refused", WT_ERR_PROTOCOL,
                   wt_qpack_encoder_stream_apply(&stream, &c, &error));
  WT_EXPECT_U64("as an encoder stream error", WT_QPACK_ERROR_ENCODER_STREAM, (uint64_t)error);

  /* An index that names an EVICTED entry: a table with room for one entry, filled
   * twice, so the first is gone and relative 1 names it. */
  {
    wt_qpack_dynamic_table_t small;
    wt_qpack_encoder_stream_t small_stream;
    size_t one_entry = 1U + 1U + (size_t)WT_QPACK_DYNAMIC_ENTRY_OVERHEAD;

    wt_qpack_dynamic_init(&small, one_entry);
    wt_qpack_encoder_stream_init(&small_stream, &small, one_entry);
    w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("the first entry writes",
                 wt_qpack_encoder_stream_write_insert_literal(&w, (const uint8_t *)"n", 1U,
                                                              (const uint8_t *)"v", 1U));
    apply(&small_stream, bytes, wt_writer_offset(&w), "and inserts");
    w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("the second entry writes",
                 wt_qpack_encoder_stream_write_insert_literal(&w, (const uint8_t *)"m", 1U,
                                                              (const uint8_t *)"w", 1U));
    apply(&small_stream, bytes, wt_writer_offset(&w), "and evicts the first");
    WT_EXPECT_U64("leaving one live entry", 1U, (uint64_t)small.count);

    w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a duplicate of the evicted one writes",
                 wt_qpack_encoder_stream_write_duplicate(&w, 1U));
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_STATUS("but applying it is refused", WT_ERR_PROTOCOL,
                     wt_qpack_encoder_stream_apply(&small_stream, &c, &error));
    WT_EXPECT_U64("as an encoder stream error", WT_QPACK_ERROR_ENCODER_STREAM, (uint64_t)error);
  }

  /* A truncated instruction: an insert whose value length runs past the bytes. */
  {
    static const uint8_t short_insert[2] = {0x40U, 0x05U};
    c = wt_cursor_init(short_insert, sizeof(short_insert));
    WT_EXPECT_STATUS("a truncated insertion is refused", WT_ERR_TRUNCATED,
                     wt_qpack_encoder_stream_apply(&stream, &c, &error));
    /* Incomplete rather than malformed: the rest may still arrive on the stream, so
     * there is no error to send the peer yet. */
    WT_EXPECT_U64("with no error to send yet", (uint64_t)WT_QPACK_ERROR_NONE, (uint64_t)error);
  }

  /* And an empty stream is not an instruction. */
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("an empty buffer is refused", WT_ERR_TRUNCATED,
                   wt_qpack_encoder_stream_apply(&stream, &c, &error));
}

int main(void) {
  test_capacity();
  test_insertions();
  test_duplicate_and_errors();
  WT_TEST_MAIN_END("wt_qpack_encoder_stream");
}
