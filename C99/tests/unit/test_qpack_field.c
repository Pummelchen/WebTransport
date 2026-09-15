/* QPACK's field line representations (RFC 9204 section 4.5).
 *
 * Each form's first byte is a prefix code, so the wire bytes are asserted by hand
 * for one line of each kind: a wrong prefix would decode a representation as a
 * different one, and a round trip through the same code cannot see that. The rest
 * covers what a caller has to be able to tell apart -- the static forms resolve to
 * a name, the dynamic and post-base ones do not (there is no dynamic table yet),
 * and a truncated value is a truncation rather than a malformed line. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static void expect_wire(const wt_qpack_field_line_t *line, const uint8_t *want, size_t want_length,
                        const char *label) {
  uint8_t buffer[32];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  size_t length = 0U;

  WT_EXPECT_OK(label, wt_qpack_field_line_encode(&w, line));
  length = wt_writer_offset(&w);
  WT_EXPECT_U64("with the expected length", (uint64_t)want_length, (uint64_t)length);
  WT_EXPECT_BYTES("and the expected bytes", want, buffer, length);
}

static void test_static_indexed(void) {
  /* 1 1 index(6+): the static table's entry 1 is :path /, so 0xc1 is five bits of
   * pattern and a one-byte index. */
  static const uint8_t want[1] = {0xc1U};
  wt_cursor_t c;
  wt_qpack_field_line_t line;
  wt_qpack_field_line_t decoded;
  const char *name = NULL;
  size_t name_length = 0U;

  memset(&line, 0, sizeof(line));
  line.kind = WT_QPACK_FIELD_INDEXED_STATIC;
  line.index = 1U;
  expect_wire(&line, want, sizeof(want), "a static indexed line encodes");

  /* Decoded from the expected bytes rather than from the encoder's output, so a
   * shared mistake in both directions cannot hide here. */
  c = wt_cursor_init(want, sizeof(want));
  WT_EXPECT_OK("and decodes", wt_qpack_field_line_decode(&c, &decoded));
  WT_EXPECT_INT("as an indexed static line", (int)WT_QPACK_FIELD_INDEXED_STATIC, (int)decoded.kind);
  WT_EXPECT_U64("with its index", 1U, decoded.index);
  WT_EXPECT_U64("and its bytes consumed", 1U, (uint64_t)decoded.bytes_consumed);
  WT_EXPECT_OK("whose name comes from the table",
               wt_qpack_field_line_static_name(&decoded, &name, &name_length));
  WT_EXPECT_U64("as :path", 5U, (uint64_t)name_length);
  WT_EXPECT_BYTES("spelled out", (const uint8_t *)":path", (const uint8_t *)name, 5U);

  /* A dynamic index is the same line with T clear, and it must NOT resolve against
   * the static table: that is the mistake that silently changes a header. */
  {
    static const uint8_t dynamic[1] = {0x81U};
    c = wt_cursor_init(dynamic, 1U);
    WT_EXPECT_OK("a dynamic indexed line decodes", wt_qpack_field_line_decode(&c, &decoded));
    WT_EXPECT_INT("as a dynamic one", (int)WT_QPACK_FIELD_INDEXED_DYNAMIC, (int)decoded.kind);
    WT_EXPECT_STATUS("and does not resolve here", WT_ERR_STATE,
                     wt_qpack_field_line_static_name(&decoded, &name, &name_length));
  }
}

static void test_literal_forms(void) {
  /* 01 N T index(4+) then the value: static, not never-indexed, index 15 (:method),
   * value CONNECT (not Huffman-coded). */
  static const uint8_t want[10] = {0x5fU, 0x00U, 0x07U, 'C', 'O', 'N', 'N', 'E', 'C', 'T'};
  uint8_t buffer[32];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_cursor_t c;
  wt_qpack_field_line_t line;
  wt_qpack_field_line_t decoded;

  memset(&line, 0, sizeof(line));
  line.kind = WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC;
  line.index = 15U;
  line.value = (const uint8_t *)"CONNECT";
  line.value_length = 7U;
  expect_wire(&line, want, sizeof(want), "a literal with a static name reference encodes");

  c = wt_cursor_init(want, sizeof(want));
  WT_EXPECT_OK("and decodes", wt_qpack_field_line_decode(&c, &decoded));
  WT_EXPECT_INT("as a static name reference", (int)WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC,
                (int)decoded.kind);
  WT_EXPECT_U64("with its name index", 15U, decoded.index);
  WT_EXPECT_U64("its value length", 7U, (uint64_t)decoded.value_length);
  WT_EXPECT_BYTES("and its value", (const uint8_t *)"CONNECT", decoded.value, 7U);
  WT_EXPECT_INT("not marked never-indexed", 0, decoded.never_indexed);

  /* 001 N H name-length(3+) then the name and the value: the literal-literal form,
   * with the name inline and a five-byte value. */
  w = wt_writer_init(buffer, sizeof(buffer));
  memset(&line, 0, sizeof(line));
  line.kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  line.never_indexed = 1;
  line.name = (const uint8_t *)"x-test";
  line.name_length = 6U;
  line.value = (const uint8_t *)"value";
  line.value_length = 5U;
  WT_EXPECT_OK("a literal name line encodes", wt_qpack_field_line_encode(&w, &line));
  WT_EXPECT_U64("with the 001 pattern, N set", 0x36U, (uint64_t)buffer[0]);
  c = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_qpack_field_line_decode(&c, &decoded));
  WT_EXPECT_INT("as a literal name", (int)WT_QPACK_FIELD_LITERAL_LITERAL_NAME, (int)decoded.kind);
  WT_EXPECT_INT("never-indexed", 1, decoded.never_indexed);
  WT_EXPECT_U64("with its name length", 6U, (uint64_t)decoded.name_length);
  WT_EXPECT_BYTES("its name", (const uint8_t *)"x-test", decoded.name, 6U);
  WT_EXPECT_BYTES("and its value", (const uint8_t *)"value", decoded.value, 5U);
  {
    const char *name = NULL;
    size_t name_length = 0U;
    WT_EXPECT_OK("and the inline name is the field's name",
                 wt_qpack_field_line_static_name(&decoded, &name, &name_length));
    WT_EXPECT_BYTES("unchanged", (const uint8_t *)"x-test", (const uint8_t *)name, 6U);
  }
}

static void test_post_base_and_truncation(void) {
  static const uint8_t post_base_index[1] = {0x10U};
  /* 0x41 is a literal with a static name reference and index 0; the 0x05 that
   * follows says its value is five bytes, and there are none. */
  static const uint8_t truncated_value[2] = {0x41U, 0x05U};
  wt_cursor_t c;
  wt_qpack_field_line_t decoded;

  /* 0001 index(4+): a post-base index of zero. */
  c = wt_cursor_init(post_base_index, 1U);
  WT_EXPECT_OK("a post-base indexed line decodes", wt_qpack_field_line_decode(&c, &decoded));
  WT_EXPECT_INT("as a post-base index", (int)WT_QPACK_FIELD_POST_BASE_INDEX, (int)decoded.kind);
  WT_EXPECT_U64("with its index", 0U, decoded.index);

  /* A name reference whose value length is longer than the bytes present. */
  c = wt_cursor_init(truncated_value, sizeof(truncated_value));
  WT_EXPECT_STATUS("a value longer than its bytes is truncated", WT_ERR_TRUNCATED,
                   wt_qpack_field_line_decode(&c, &decoded));

  /* And an empty buffer is not a line at all. */
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("an empty buffer is truncated", WT_ERR_TRUNCATED,
                   wt_qpack_field_line_decode(&c, &decoded));
}

/* A name length is a varint from the peer (up to 2^62-1) and the decoder stores it in a size_t. The narrowing
 * must be CHECKED, not cast: on a target whose size_t is narrower than 64 bits, `(size_t)name_length` truncates,
 * so a name the peer says is 2^32+1 bytes long becomes a one-byte name and the value that follows is read from
 * the wrong offset -- the whole line is mis-parsed. The bytes below are written by hand (the literal-literal
 * form's 001 pattern, then the length 2^32+1 as a QPACK prefixed integer, then a name byte and an empty value),
 * because the encoder writes the same size_t the decoder reads and a round trip cannot see a truncation. */
static void test_a_name_length_wider_than_size_t_is_refused(void) {
  /* 0x27: 001 pattern, N and H clear, the 3-bit name-length prefix saturated at 7; then
   * (2^32+1)-7 = 4294967290 in base-128 groups: 0xfa 0xff 0xff 0xff 0x0f. A one-byte name follows (0x00), and
   * then an empty value string (0x00). */
  static const uint8_t wire[] = {0x27U, 0xfaU, 0xffU, 0xffU, 0xffU, 0x0fU, 0x00U, 0x00U};
  wt_cursor_t c;
  wt_qpack_field_line_t decoded;

  c = wt_cursor_init(wire, sizeof(wire));
#if SIZE_MAX < UINT64_MAX
  /* 32-bit: the length does not fit size_t, so the line is malformed. Before the checked narrowing this call
   * returned WT_OK with a one-byte name (the bytes above were built to make that visible). */
  WT_EXPECT_STATUS("a name length wider than size_t is refused", WT_ERR_PROTOCOL,
                   wt_qpack_field_line_decode(&c, &decoded));
#else
  /* 64-bit: the length fits size_t but names more bytes than the cursor holds, which is a truncation and not a
   * narrowing. This half keeps the test meaningful on a target that cannot reach the branch above. */
  WT_EXPECT_STATUS("a name longer than the cursor is truncated", WT_ERR_TRUNCATED,
                   wt_qpack_field_line_decode(&c, &decoded));
#endif
}

int main(void) {
  test_static_indexed();
  test_literal_forms();
  test_post_base_and_truncation();
  test_a_name_length_wider_than_size_t_is_refused();
  WT_TEST_MAIN_END("wt_qpack_field");
}
