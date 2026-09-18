/* Decoding a QPACK field section's lines (RFC 9204 sections 4.5 and 3.2.5).
 *
 * This is where the pieces meet: a prefix, the static table, the dynamic table, and
 * the index arithmetic that ties a line to an entry. The arithmetic is the part worth
 * testing hard, because it is the only place the two directions of a relative index
 * live -- `Base - Index - 1` for a dynamic reference and `Base + Index` for a
 * post-base one -- and a sign error there resolves to a DIFFERENT but valid entry,
 * which nothing later can detect. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/http3/qpack.h"

/* One dynamic table with two entries: "x-a: one" then "x-b: two", so the absolute
 * indices are 0 and 1 and the Base for a section naming the newest is 2. */
static void fill_table(wt_qpack_dynamic_table_t *table) {
  uint64_t index = 0U;
  wt_qpack_dynamic_init(table, 4096U);
  WT_EXPECT_OK("the first entry inserts",
               wt_qpack_dynamic_insert(table, (const uint8_t *)"x-a", 3U, (const uint8_t *)"one",
                                       3U, &index));
  WT_EXPECT_OK("and the second", wt_qpack_dynamic_insert(table, (const uint8_t *)"x-b", 3U,
                                                         (const uint8_t *)"two", 3U, &index));
}

static void write_line(wt_writer_t *w, wt_qpack_field_kind_t kind, uint64_t index,
                       const char *value) {
  wt_qpack_field_line_t line;
  memset(&line, 0, sizeof(line));
  line.kind = kind;
  line.index = index;
  line.value = (const uint8_t *)value;
  line.value_length = value == NULL ? 0U : strlen(value);
  WT_EXPECT_OK("the line writes", wt_qpack_field_line_encode(w, &line));
}

static void test_static_forms(void) {
  /* The section's cursor into the scratch, shared by every field of one section: what a */
  /* resolved field points at must stay valid until the section is finished (WT-154). */
  size_t scratch_used = 0U;
  wt_qpack_dynamic_table_t table;
  wt_qpack_header_prefix_t prefix = {0U, 0U};
  uint8_t bytes[32];
  uint8_t scratch[64];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_resolved_field_t field;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  fill_table(&table);

  /* A static indexed line needs no table beyond the static one. */
  w = wt_writer_init(bytes, sizeof(bytes));
  write_line(&w, WT_QPACK_FIELD_INDEXED_STATIC, 1U, NULL);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("a static indexed line resolves",
               wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                           &scratch_used, &field, &error));
  WT_EXPECT_BYTES("to :path", (const uint8_t *)":path", field.name, 5U);
  WT_EXPECT_BYTES("with the value from the table", (const uint8_t *)"/", field.value, 1U);
  WT_EXPECT_STATUS("and then the section is finished", WT_ERR_CLOSED,
                   wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                               &scratch_used, &field, &error));

  /* A literal with a static name reference: the name from the table, the value from
   * the line. */
  w = wt_writer_init(bytes, sizeof(bytes));
  write_line(&w, WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC, 15U, "NOTGET");
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("a literal with a static name resolves",
               wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                           &scratch_used, &field, &error));
  WT_EXPECT_BYTES("to :method", (const uint8_t *)":method", field.name, 7U);
  WT_EXPECT_BYTES("with the line's value", (const uint8_t *)"NOTGET", field.value, 6U);
}

static void test_dynamic_references(void) {
  /* The section's cursor into the scratch, shared by every field of one section: what a */
  /* resolved field points at must stay valid until the section is finished (WT-154). */
  size_t scratch_used = 0U;
  wt_qpack_dynamic_table_t table;
  uint8_t bytes[32];
  uint8_t scratch[64];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_resolved_field_t field;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  fill_table(&table);

  /* Base 2, dynamic index 0: absolute = 2 - 0 - 1 = 1, the NEWEST entry. */
  {
    wt_qpack_header_prefix_t prefix = {2U, 2U};
    w = wt_writer_init(bytes, sizeof(bytes));
    write_line(&w, WT_QPACK_FIELD_INDEXED_DYNAMIC, 0U, NULL);
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_OK("a dynamic indexed line resolves",
                 wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                             &scratch_used, &field, &error));
    WT_EXPECT_BYTES("to the newest entry's name", (const uint8_t *)"x-b", field.name, 3U);
    WT_EXPECT_BYTES("and its value", (const uint8_t *)"two", field.value, 3U);
  }

  /* The same Base with index 1 names the OLDER entry: 2 - 1 - 1 = 0. A sign error in
   * the arithmetic would resolve index 1 to x-b as well, which is why the two cases
   * are asserted separately. */
  {
    wt_qpack_header_prefix_t prefix = {2U, 2U};
    w = wt_writer_init(bytes, sizeof(bytes));
    write_line(&w, WT_QPACK_FIELD_INDEXED_DYNAMIC, 1U, NULL);
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_OK("the next index resolves",
                 wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                             &scratch_used, &field, &error));
    WT_EXPECT_BYTES("to the older entry's name", (const uint8_t *)"x-a", field.name, 3U);
    WT_EXPECT_BYTES("and its value", (const uint8_t *)"one", field.value, 3U);
  }

  /* A post-base reference counts UP: Base 0 with index 1 is absolute 1. */
  {
    wt_qpack_header_prefix_t prefix = {2U, 0U};
    w = wt_writer_init(bytes, sizeof(bytes));
    write_line(&w, WT_QPACK_FIELD_POST_BASE_INDEX, 1U, NULL);
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_OK("a post-base index resolves",
                 wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                             &scratch_used, &field, &error));
    WT_EXPECT_BYTES("to the entry above the base", (const uint8_t *)"x-b", field.name, 3U);
    WT_EXPECT_BYTES("with its value", (const uint8_t *)"two", field.value, 3U);
  }

  /* A dynamic name reference with the value from the line. */
  {
    wt_qpack_header_prefix_t prefix = {2U, 2U};
    w = wt_writer_init(bytes, sizeof(bytes));
    write_line(&w, WT_QPACK_FIELD_LITERAL_NAME_REF_DYNAMIC, 0U, "else");
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_OK("a dynamic name reference resolves",
                 wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                             &scratch_used, &field, &error));
    WT_EXPECT_BYTES("with the entry's name", (const uint8_t *)"x-b", field.name, 3U);
    WT_EXPECT_BYTES("and the line's value", (const uint8_t *)"else", field.value, 4U);
  }

  /* An index at the Base names nothing: 2 - 2 - 1 would underflow. */
  {
    wt_qpack_header_prefix_t prefix = {2U, 2U};
    w = wt_writer_init(bytes, sizeof(bytes));
    write_line(&w, WT_QPACK_FIELD_INDEXED_DYNAMIC, 2U, NULL);
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_STATUS("an index at the base is refused", WT_ERR_PROTOCOL,
                     wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                                 &scratch_used, &field, &error));
    WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED,
                  (uint64_t)error);
  }

  /* And one past the end of the table: Base 2 with index 1 is absolute 0 only if the
   * entry is still there, so an evicted table makes it unresolvable. */
  {
    wt_qpack_dynamic_table_t small;
    wt_qpack_header_prefix_t prefix = {2U, 2U};
    /* Room for exactly the one entry inserted below: 3 + 5 + the 32-byte
     * overhead, which is what section 3.2.1 counts. */
    size_t one_entry = 3U + 5U + (size_t)WT_QPACK_DYNAMIC_ENTRY_OVERHEAD;
    uint64_t index = 0U;

    wt_qpack_dynamic_init(&small, one_entry);
    WT_EXPECT_OK("a table with one entry",
                 wt_qpack_dynamic_insert(&small, (const uint8_t *)"x-c", 3U,
                                         (const uint8_t *)"three", 5U, &index));
    /* Base 2 with index 0 names absolute 1, which this one-entry table has never
     * held: the entry is not there, and section 4.5.1 makes that a decompression
     * failure rather than a lookup that falls back to something else. */
    w = wt_writer_init(bytes, sizeof(bytes));
    write_line(&w, WT_QPACK_FIELD_INDEXED_DYNAMIC, 0U, NULL);
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_STATUS("an entry that is not there is refused", WT_ERR_PROTOCOL,
                     wt_qpack_field_section_next(&c, &prefix, &small, scratch, sizeof(scratch),
                                                 &scratch_used, &field, &error));
    WT_EXPECT_U64("as a decompression failure", WT_QPACK_ERROR_DECOMPRESSION_FAILED,
                  (uint64_t)error);
  }
}

static void test_inline_and_huffman(void) {
  /* The section's cursor into the scratch, shared by every field of one section: what a */
  /* resolved field points at must stay valid until the section is finished (WT-154). */
  size_t scratch_used = 0U;
  wt_qpack_dynamic_table_t table;
  wt_qpack_header_prefix_t prefix = {0U, 0U};
  uint8_t bytes[32];
  uint8_t scratch[64];
  wt_writer_t w;
  wt_cursor_t c;
  wt_qpack_resolved_field_t field;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;

  fill_table(&table);

  /* A literal-literal line: both halves inline, neither Huffman-coded. */
  w = wt_writer_init(bytes, sizeof(bytes));
  {
    wt_qpack_field_line_t line;
    memset(&line, 0, sizeof(line));
    line.kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
    line.name = (const uint8_t *)"x-test";
    line.name_length = 6U;
    line.value = (const uint8_t *)"value";
    line.value_length = 5U;
    WT_EXPECT_OK("a literal-literal line writes", wt_qpack_field_line_encode(&w, &line));
  }
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and resolves",
               wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                           &scratch_used, &field, &error));
  WT_EXPECT_BYTES("to its inline name", (const uint8_t *)"x-test", field.name, 6U);
  WT_EXPECT_BYTES("and inline value", (const uint8_t *)"value", field.value, 5U);

  /* The same line with both halves Huffman-coded, written by this build's coded
   * encoder: the line it produces must decode to the same plain strings. */
  w = wt_writer_init(bytes, sizeof(bytes));
  {
    wt_qpack_field_line_t line;
    uint8_t line_scratch[64];

    memset(&line, 0, sizeof(line));
    line.kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
    line.name_huffman = 1;
    line.name = (const uint8_t *)"x-test";
    line.name_length = 6U;
    line.value_huffman = 1;
    line.value = (const uint8_t *)"value";
    line.value_length = 5U;
    WT_EXPECT_OK("the coded line writes",
                 wt_qpack_field_line_encode_coded(&w, &line, line_scratch, sizeof(line_scratch)));
    /* The plain encoder refuses it: the flags are part of the representation, and a
     * plain string with the H bit clear is a different line. */
    {
      uint8_t plain[32];
      wt_writer_t plain_writer = wt_writer_init(plain, sizeof(plain));
      WT_EXPECT_STATUS("while the plain encoder refuses it", WT_ERR_STATE,
                       wt_qpack_field_line_encode(&plain_writer, &line));
    }
  }
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and resolves",
               wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                           &scratch_used, &field, &error));
  WT_EXPECT_BYTES("to the decoded name", (const uint8_t *)"x-test", field.name, 6U);
  WT_EXPECT_BYTES("and the decoded value", (const uint8_t *)"value", field.value, 5U);

  /* The hand-built variant below keeps its place as the check that the reader is not
   * reading its own writer's dialect. The line is built BY HAND rather
   * than through `wt_qpack_field_line_encode`, because that encoder's string writer
   * only writes plain strings -- the H bit on the way out is a piece this build does
   * not have yet, and a test that used the encoder here would be testing a line the
   * encoder cannot produce. The bytes below are what section 4.5.3's figure says:
   * the 001 pattern with H set (0x20 | 0x08) and no N, the name length below it,
   * the coded name, then a string whose length byte has the H bit set. */
  w = wt_writer_init(bytes, sizeof(bytes));
  {
    uint8_t name_bytes[16];
    uint8_t value_bytes[16];
    size_t name_length = 0U;
    size_t value_length = 0U;

    WT_EXPECT_OK("the name huffman-encodes",
                 wt_qpack_huffman_encode((const uint8_t *)"x-test", 6U, name_bytes,
                                         sizeof(name_bytes), &name_length));
    WT_EXPECT_OK("and the value", wt_qpack_huffman_encode((const uint8_t *)"value", 5U, value_bytes,
                                                          sizeof(value_bytes), &value_length));
    WT_EXPECT_OK("the name length writes",
                 wt_qpack_integer_encode(&w, 3U, 0x28U, (uint64_t)name_length));
    if (name_length != 0U) wt_writer_bytes(&w, name_bytes, name_length);
    WT_EXPECT_OK("and the value string with its H bit",
                 wt_qpack_integer_encode(&w, 7U, 0x80U, (uint64_t)value_length));
    if (value_length != 0U) wt_writer_bytes(&w, value_bytes, value_length);
  }
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and resolves",
               wt_qpack_field_section_next(&c, &prefix, &table, scratch, sizeof(scratch),
                                           &scratch_used, &field, &error));
  WT_EXPECT_BYTES("to the decoded name", (const uint8_t *)"x-test", field.name, 6U);
  WT_EXPECT_BYTES("and the decoded value", (const uint8_t *)"value", field.value, 5U);
  WT_EXPECT_TRUE("leaving nothing behind", wt_cursor_at_end(&c));

  /* A scratch buffer too small for the decoded strings is the CALLER's limit, not a
   * decompression failure. */
  {
    uint8_t tiny[2];
    /* A NEW section, so the scratch cursor starts again: the assertion is about the buffer being too small for
     * this section's strings, not about what the previous one left in it. */
    scratch_used = 0U;
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_STATUS("a scratch buffer that is too small is a limit", WT_ERR_LIMIT,
                     wt_qpack_field_section_next(&c, &prefix, &table, tiny, sizeof(tiny),
                                                 &scratch_used, &field, &error));
    WT_EXPECT_U64("with no error to send the peer", (uint64_t)WT_QPACK_ERROR_NONE, (uint64_t)error);
  }
}

/* A field section that a THIRD-PARTY encoder produced, byte for byte (WT-154).
 *
 * pywebtransport/aioquic sent this CONNECT to `wt-server-c99`, and this decoder read `:protocol` as
 * "localhostort" -- "localhost", the LATER field's value, written over the head of "webtransport" and leaving
 * the tail of the old value behind. The prefix and the field lines are:
 *
 *   00 00                     required insert count 0, base 0
 *   cf                        indexed, static 15          -> :method: CONNECT
 *   2f 00 <7 bytes> 89 <9>    literal, literal NAME (7 Huffman bytes), VALUE 9 Huffman bytes
 *   d7                        indexed, static 23          -> :scheme: https
 *   c1                        indexed, static 1           -> :path: /
 *   50 86 <6 bytes>           literal with NAME REFERENCE (static 0), value 6 Huffman bytes
 *
 * pylsqpack decodes it to the five pseudo-headers below, so the expectation is an independent implementation's
 * reading rather than this tree's. The bug is why our own encoder never showed it: it does not produce a literal
 * with a literAL name, so every test in the tree agreed with every other one. */
static void test_a_third_party_section_decodes_every_field(void) {
  static const uint8_t k_section[] = {0x00U, 0x00U, 0xcfU, 0x2fU, 0x00U, 0xb9U, 0x5dU, 0x87U,
                                      0x49U, 0xc8U, 0x7aU, 0x3fU, 0x89U, 0xf0U, 0x58U, 0xd3U,
                                      0x60U, 0xeaU, 0x45U, 0x67U, 0xb1U, 0x3fU, 0xd7U, 0xc1U,
                                      0x50U, 0x86U, 0xa0U, 0xe4U, 0x1dU, 0x13U, 0x9dU, 0x09U};
  static const struct {
    const char *name;
    const char *value;
  } k_expected[5] = {
      {":method", "CONNECT"}, {":protocol", "webtransport"}, {":scheme", "https"},
      {":path", "/"},         {":authority", "localhost"},
  };
  wt_qpack_field_section_decoder_t decoder;
  wt_qpack_dynamic_table_t table;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;
  wt_qpack_header_prefix_t prefix;
  uint8_t scratch[256];
  size_t index;

  wt_qpack_dynamic_init(&table, 0U);
  /* The prefix is read by the walker's caller, exactly as `wt_http3_message_decode` does it. */
  {
    wt_cursor_t c = wt_cursor_init(k_section, sizeof(k_section));
    WT_EXPECT_OK("the third-party prefix reads",
                 wt_qpack_header_prefix_decode(&c, 0U, 0U, &prefix, &error));
  }
  WT_EXPECT_OK(
      "the third-party section begins",
      wt_qpack_field_section_begin(&decoder, &table, 0U, k_section, sizeof(k_section), 0U, &error));

  /* EVERY field is read first and asserted afterwards, which is the whole point: the values have to survive the
   * fields that follow them, and a decoder that decodes them into the same bytes cannot pass this. */
  {
    wt_qpack_resolved_field_t fields[5];
    memset(fields, 0, sizeof(fields));
    for (index = 0U; index < 5U; index++) {
      WT_EXPECT_OK("a field resolves",
                   wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch),
                                                       &fields[index], &error));
    }
    for (index = 0U; index < 5U; index++) {
      WT_EXPECT_BYTES("with the name the peer sent", (const uint8_t *)k_expected[index].name,
                      fields[index].name, strlen(k_expected[index].name));
      WT_EXPECT_BYTES("and the value the peer sent", (const uint8_t *)k_expected[index].value,
                      fields[index].value, strlen(k_expected[index].value));
    }
    WT_EXPECT_STATUS("and the section is finished", WT_ERR_CLOSED,
                     wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch),
                                                         &fields[0], &error));
  }
}

int main(void) {
  test_static_forms();
  test_a_third_party_section_decodes_every_field();
  test_dynamic_references();
  test_inline_and_huffman();
  WT_TEST_MAIN_END("wt_qpack_field_section");
}
