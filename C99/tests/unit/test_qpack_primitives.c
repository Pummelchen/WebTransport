/* QPACK's prefixed integers and strings (RFC 9204 section 4.1).
 *
 * These two primitives carry every QPACK representation, so the tests are about
 * their edges rather than their common case: the value that exactly fills the
 * prefix (which changes the encoding), the value one below it, the 62-bit bound
 * the section sets, a continuation that never ends, a string whose length is
 * truncated, and the H bit, which this build returns rather than decoding -- a
 * caller that ignored it would read Huffman-coded bytes as field content. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static void test_integer_round_trip(void) {
  static const uint64_t values[] = {0U, 1U, 2U, 5U, 30U, 31U, 32U, 62U, 63U, 64U,
                                    126U, 127U, 128U, 1337U, 100000U};
  unsigned bits;

  for (bits = 1U; bits <= 8U; bits++) {
    uint64_t prefix_max = ((uint64_t)1U << bits) - 1U;
    size_t i;
    for (i = 0U; i < sizeof(values) / sizeof(values[0]); i++) {
      uint8_t buffer[16];
      wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
      wt_cursor_t c;
      uint64_t decoded = 0U;

      WT_EXPECT_OK("an integer encodes",
                   wt_qpack_integer_encode(&w, bits, 0U, values[i]));
      /* The prefix boundary is where the encoding changes shape, so it is
       * exercised through the boundary itself rather than only through values
       * that are far from it. */
      if (values[i] < prefix_max) {
        WT_EXPECT_U64("in one byte below the prefix maximum", 1U,
                      (uint64_t)wt_writer_offset(&w));
      }
      c = wt_cursor_init(buffer, wt_writer_offset(&w));
      WT_EXPECT_OK("and decodes", wt_qpack_integer_decode(&c, bits, &decoded));
      WT_EXPECT_U64("to the same value", values[i], decoded);
      WT_EXPECT_TRUE("leaving nothing behind", wt_cursor_at_end(&c));
    }
  }

  /* The 62-bit bound is the section's, and the largest value it allows round
   * trips like any other. */
  {
    uint8_t buffer[16];
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_cursor_t c;
    uint64_t decoded = 0U;

    WT_EXPECT_OK("the largest integer encodes",
                 wt_qpack_integer_encode(&w, 8U, 0U, (uint64_t)0x3fffffffffffffffULL));
    c = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_OK("and decodes", wt_qpack_integer_decode(&c, 8U, &decoded));
    WT_EXPECT_U64("to itself", (uint64_t)0x3fffffffffffffffULL, decoded);
    WT_EXPECT_STATUS("and one above it is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_qpack_integer_encode(&w, 8U, 0U, (uint64_t)0x4000000000000000ULL));
  }
}

static void test_integer_edges(void) {
  uint8_t buffer[8];
  wt_cursor_t c;
  uint64_t decoded = 0U;
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));

  /* The pattern bits above the prefix are written and read back as the caller's,
   * not as part of the value: 0x80 with a 7-bit prefix is the indexed field line
   * pattern, whose value is the index. */
  WT_EXPECT_OK("a flagged integer encodes", wt_qpack_integer_encode(&w, 7U, 0x80U, 3U));
  WT_EXPECT_U64("as one byte", 1U, (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_U64("with the flag set", 0x83U, (uint64_t)buffer[0]);
  c = wt_cursor_init(buffer, 1U);
  WT_EXPECT_OK("and decodes", wt_qpack_integer_decode(&c, 7U, &decoded));
  WT_EXPECT_U64("to the value without the flag", 3U, decoded);

  /* A flag inside the prefix would collide with the value's low bits; the bit
   * just above a four-bit prefix does not, and is allowed. */
  WT_EXPECT_STATUS("a flag inside the prefix is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_qpack_integer_encode(&w, 4U, 0x01U, 1U));
  WT_EXPECT_OK("but the bit above the prefix is a flag like any other",
               wt_qpack_integer_encode(&w, 4U, 0x10U, 1U));
  WT_EXPECT_STATUS("a prefix of zero bits is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_qpack_integer_encode(&w, 0U, 0U, 1U));

  /* An empty buffer has no first byte. */
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("an empty buffer is truncated", WT_ERR_TRUNCATED,
                   wt_qpack_integer_decode(&c, 7U, &decoded));

  /* A continuation that never ends: every byte keeps the high bit. */
  {
    static const uint8_t endless[4] = {0x7fU, 0x80U, 0x80U, 0x80U};
    c = wt_cursor_init(endless, sizeof(endless));
    WT_EXPECT_STATUS("a continuation that runs out is truncated", WT_ERR_TRUNCATED,
                     wt_qpack_integer_decode(&c, 7U, &decoded));
  }

  /* And one that runs past 62 bits: nine continuation bytes of 0x7f reach beyond
   * the bound the section sets. */
  {
    static const uint8_t huge[12] = {0x7fU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
                                     0xffU, 0xffU, 0xffU, 0xffU, 0x01U, 0x00U};
    c = wt_cursor_init(huge, sizeof(huge));
    WT_EXPECT_STATUS("an integer beyond 62 bits is refused", WT_ERR_PROTOCOL,
                     wt_qpack_integer_decode(&c, 7U, &decoded));
  }
}

static void test_strings(void) {
  static const uint8_t content[5] = {'h', 'e', 'l', 'l', 'o'};
  uint8_t buffer[32];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_cursor_t c;
  const uint8_t *bytes = NULL;
  size_t length = 0U;
  int huffman = -1;

  WT_EXPECT_OK("a string encodes", wt_qpack_string_encode(&w, content, sizeof(content)));
  WT_EXPECT_U64("with a one-byte length first", 6U, (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_U64("and the H bit clear", 0U, (uint64_t)(buffer[0] & 0x80U));
  c = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_qpack_string_decode(&c, &bytes, &length, &huffman));
  WT_EXPECT_U64("with its length", (uint64_t)sizeof(content), (uint64_t)length);
  WT_EXPECT_BYTES("its bytes", content, bytes, sizeof(content));
  WT_EXPECT_INT("and not Huffman-coded", 0, huffman);
  WT_EXPECT_TRUE("leaving nothing behind", wt_cursor_at_end(&c));

  /* An empty string is a length of zero and no bytes. */
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_OK("an empty string encodes", wt_qpack_string_encode(&w, NULL, 0U));
  WT_EXPECT_U64("as one byte", 1U, (uint64_t)wt_writer_offset(&w));
  c = wt_cursor_init(buffer, 1U);
  WT_EXPECT_OK("and decodes", wt_qpack_string_decode(&c, &bytes, &length, &huffman));
  WT_EXPECT_U64("to nothing", 0U, (uint64_t)length);

  /* The H bit: the bytes are returned as they are, with the flag set, because
   * decoding them is the Huffman part's job. A caller that ignored the flag would
   * read coded bytes as field content. */
  {
    static const uint8_t coded[3] = {0x01U, 0x02U, 0x03U};
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_OK("a length with the H bit is written",
                 wt_qpack_integer_encode(&w, 7U, 0x80U, (uint64_t)sizeof(coded)));
    wt_writer_bytes(&w, coded, sizeof(coded));
    c = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_OK("and decodes", wt_qpack_string_decode(&c, &bytes, &length, &huffman));
    WT_EXPECT_INT("as Huffman-coded", 1, huffman);
    WT_EXPECT_BYTES("with the bytes unchanged", coded, bytes, sizeof(coded));
  }

  /* A length the buffer does not hold, and a length with no bytes after it. */
  {
    static const uint8_t short_string[2] = {0x05U, 'a'};
    c = wt_cursor_init(short_string, sizeof(short_string));
    WT_EXPECT_STATUS("a string longer than its bytes is truncated", WT_ERR_TRUNCATED,
                     wt_qpack_string_decode(&c, &bytes, &length, &huffman));
  }
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("and an empty buffer has no length", WT_ERR_TRUNCATED,
                   wt_qpack_string_decode(&c, &bytes, &length, &huffman));
}

int main(void) {
  test_integer_round_trip();
  test_integer_edges();
  test_strings();
  WT_TEST_MAIN_END("wt_qpack_primitives");
}
