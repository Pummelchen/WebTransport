/* Whole QPACK field sections (RFC 9204 sections 4.5, 4.5.1 and 2.1.2).
 *
 * The interesting rule at this layer is the BLOCKED case: a section whose Required
 * Insert Count is above what the decoder has received is not malformed, it is early.
 * RFC 9204 section 2.1.2 lets a decoder wait for the encoder stream to catch up, so the
 * status has to be distinguishable from a decompression failure -- a decoder that
 * treated "not yet" as "no" would close a connection over an instruction still in
 * flight, which is the same mistake the stream instruction parsers were corrected for.
 *
 * The rest is a whole section: a prefix, a static field, a Huffman-coded literal and a
 * dynamic reference, written by this build and read back by it. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static void test_whole_section(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_field_section_decoder_t decoder;
  wt_qpack_header_prefix_t prefix;
  wt_qpack_field_line_t lines[3];
  uint8_t section[128];
  uint8_t scratch[128];
  uint8_t line_scratch[64];
  wt_writer_t w = wt_writer_init(section, sizeof(section));
  wt_qpack_resolved_field_t field;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;
  uint64_t index = 0U;
  size_t fields = 0U;

  /* A dynamic table with one entry, and a section that references it at Base 1: index
   * 0 is absolute 0. */
  wt_qpack_dynamic_init(&table, 4096U);
  WT_EXPECT_OK("the table has an entry",
               wt_qpack_dynamic_insert(&table, (const uint8_t *)"x-dyn", 5U,
                                       (const uint8_t *)"dyn-value", 9U, &index));
  prefix.required_insert_count = 1U;
  prefix.base = 1U;

  memset(lines, 0, sizeof(lines));
  /* A static indexed field: :path /. */
  lines[0].kind = WT_QPACK_FIELD_INDEXED_STATIC;
  lines[0].index = 1U;
  /* A literal with a static name reference and a Huffman-coded value. */
  lines[1].kind = WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC;
  lines[1].index = 15U; /* :method */
  lines[1].value = (const uint8_t *)"GET";
  lines[1].value_length = 3U;
  lines[1].value_huffman = 1;
  /* A dynamic indexed field, which needs the entry inserted above. */
  lines[2].kind = WT_QPACK_FIELD_INDEXED_DYNAMIC;
  lines[2].index = 0U;

  WT_EXPECT_OK("the section writes",
               wt_qpack_field_section_encode(&w, &prefix, wt_qpack_max_entries(4096U), lines, 3U,
                                             line_scratch, sizeof(line_scratch)));

  WT_EXPECT_OK("the section begins",
               wt_qpack_field_section_begin(&decoder, &table, wt_qpack_max_entries(4096U), section,
                                            wt_writer_offset(&w), 1U, &error));
  WT_EXPECT_U64("with its required insert count", 1U, decoder.prefix.required_insert_count);
  WT_EXPECT_U64("and its base", 1U, decoder.prefix.base);

  WT_EXPECT_OK("the first field reads",
               wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch), &field,
                                                   &error));
  WT_EXPECT_BYTES("as :path", (const uint8_t *)":path", field.name, 5U);
  WT_EXPECT_BYTES("with its value", (const uint8_t *)"/", field.value, 1U);
  fields++;

  WT_EXPECT_OK("the second field reads",
               wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch), &field,
                                                   &error));
  WT_EXPECT_BYTES("as :method", (const uint8_t *)":method", field.name, 7U);
  WT_EXPECT_BYTES("with the decoded value", (const uint8_t *)"GET", field.value, 3U);
  fields++;

  WT_EXPECT_OK("the third field reads",
               wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch), &field,
                                                   &error));
  WT_EXPECT_BYTES("as the dynamic entry's name", (const uint8_t *)"x-dyn", field.name, 5U);
  WT_EXPECT_BYTES("and its value", (const uint8_t *)"dyn-value", field.value, 9U);
  fields++;

  WT_EXPECT_U64("which is all of them", 3U, (uint64_t)fields);
  WT_EXPECT_STATUS("and then the section ends", WT_ERR_CLOSED,
                   wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch), &field,
                                                       &error));
}

static void test_blocked_and_truncated(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_field_section_decoder_t decoder;
  wt_qpack_header_prefix_t prefix;
  wt_qpack_field_line_t line;
  uint8_t section[64];
  uint8_t scratch[64];
  wt_writer_t w;
  wt_qpack_resolved_field_t field;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  wt_qpack_dynamic_init(&table, 4096U);
  prefix.required_insert_count = 4U;
  prefix.base = 4U;
  memset(&line, 0, sizeof(line));
  line.kind = WT_QPACK_FIELD_INDEXED_STATIC;
  line.index = 1U;
  w = wt_writer_init(section, sizeof(section));
  WT_EXPECT_OK("a section needing four insertions writes",
               wt_qpack_field_section_encode(&w, &prefix, wt_qpack_max_entries(4096U), &line, 1U,
                                             scratch, sizeof(scratch)));

  /* Nothing has arrived yet: the section is early, not broken. */
  WT_EXPECT_STATUS("a section ahead of the insertions is blocked", WT_ERR_AGAIN,
                   wt_qpack_field_section_begin(&decoder, &table, wt_qpack_max_entries(4096U),
                                                section, wt_writer_offset(&w), 0U, &error));
  WT_EXPECT_U64("with no error to send the peer", (uint64_t)WT_QPACK_ERROR_NONE, (uint64_t)error);

  /* With the insertions in place it reads. */
  {
    uint64_t index = 0U;
    size_t i;
    for (i = 0U; i < 4U; i++) {
      WT_EXPECT_OK("an insertion arrives",
                   wt_qpack_dynamic_insert(&table, (const uint8_t *)"n", 1U, (const uint8_t *)"v",
                                           1U, &index));
    }
  }
  WT_EXPECT_OK("and then it begins",
               wt_qpack_field_section_begin(&decoder, &table, wt_qpack_max_entries(4096U), section,
                                            wt_writer_offset(&w), 4U, &error));
  WT_EXPECT_OK("with its field readable",
               wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch), &field,
                                                   &error));

  /* A section that stops inside its prefix is incomplete rather than malformed. */
  WT_EXPECT_STATUS("a truncated section is incomplete", WT_ERR_TRUNCATED,
                   wt_qpack_field_section_begin(&decoder, &table, wt_qpack_max_entries(4096U),
                                                section, 1U, 0U, &error));
  WT_EXPECT_U64("with no error to send yet", (uint64_t)WT_QPACK_ERROR_NONE, (uint64_t)error);
}

int main(void) {
  test_whole_section();
  test_blocked_and_truncated();
  WT_TEST_MAIN_END("wt_qpack_field_section_codec");
}
