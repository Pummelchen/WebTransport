/* QUIC variable-length integers (RFC 9000 section 16).
 *
 * The encodings are checked against the byte strings the RFC's table implies
 * rather than only round-tripping, because an encoder and a decoder that agree
 * on the wrong prefix round-trip perfectly. The boundary values are the point:
 * 63 and 64 are the two sides of the one-byte limit, and 2^62 - 1 is the largest
 * value the wire can carry.
 */

#include "wt_test.h"

#include "webtransport/quic/varint.h"

int main(void) {
  uint8_t buffer[8];
  wt_cursor_t c;
  uint64_t value = 0U;
  size_t size = 0U;
  size_t written = 0U;

  /* The four sizes, at both ends of each range. */
  WT_EXPECT_U64("0 is one byte", 1U, wt_quic_varint_size(0U));
  WT_EXPECT_U64("63 is one byte", 1U, wt_quic_varint_size(63U));
  WT_EXPECT_U64("64 is two bytes", 2U, wt_quic_varint_size(64U));
  WT_EXPECT_U64("16383 is two bytes", 2U, wt_quic_varint_size(16383U));
  WT_EXPECT_U64("16384 is four bytes", 4U, wt_quic_varint_size(16384U));
  WT_EXPECT_U64("1073741823 is four bytes", 4U, wt_quic_varint_size(1073741823U));
  WT_EXPECT_U64("1073741824 is eight bytes", 8U, wt_quic_varint_size(1073741824U));
  WT_EXPECT_U64("2^62-1 is eight bytes", 8U, wt_quic_varint_size(WT_QUIC_VARINT_MAX));
  /* Above the wire's range there is no encoding, and the size says so with 0
   * rather than by returning 8 and letting the caller truncate. */
  WT_EXPECT_U64("2^62 has no encoding", 0U, wt_quic_varint_size(UINT64_C(1) << 62));
  WT_EXPECT_U64("UINT64_MAX has no encoding", 0U, wt_quic_varint_size(UINT64_MAX));

  /* The encodings, byte for byte. RFC 9000 section 16's examples: 37 is
   * 0x25, 15293 is 0x7bbd, 494878333 is 0x9d7f3e7d, and 151288809941952652 is
   * 0xc2197c5eff14e88c. */
  written = wt_quic_varint_encode(37U, buffer, sizeof(buffer));
  WT_EXPECT_U64("37 is one byte", 1U, written);
  WT_EXPECT_BYTES("37 is 0x25", (const uint8_t *)"\x25", buffer, 1U);

  written = wt_quic_varint_encode(15293U, buffer, sizeof(buffer));
  WT_EXPECT_U64("15293 is two bytes", 2U, written);
  WT_EXPECT_BYTES("15293 is 0x7bbd", (const uint8_t *)"\x7b\xbd", buffer, 2U);

  written = wt_quic_varint_encode(494878333U, buffer, sizeof(buffer));
  WT_EXPECT_U64("494878333 is four bytes", 4U, written);
  WT_EXPECT_BYTES("494878333 is 0x9d7f3e7d", (const uint8_t *)"\x9d\x7f\x3e\x7d", buffer, 4U);

  written = wt_quic_varint_encode(UINT64_C(151288809941952652), buffer, sizeof(buffer));
  WT_EXPECT_U64("the RFC's eight-byte example", 8U, written);
  WT_EXPECT_BYTES("is 0xc2197c5eff14e88c", (const uint8_t *)"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c",
                  buffer, 8U);

  /* The boundaries again, encoded: 63 is 0x3f and 64 is 0x4040. */
  written = wt_quic_varint_encode(63U, buffer, sizeof(buffer));
  WT_EXPECT_BYTES("63 is 0x3f", (const uint8_t *)"\x3f", buffer, 1U);
  written = wt_quic_varint_encode(64U, buffer, sizeof(buffer));
  WT_EXPECT_BYTES("64 is 0x4040", (const uint8_t *)"\x40\x40", buffer, 2U);
  written = wt_quic_varint_encode(WT_QUIC_VARINT_MAX, buffer, sizeof(buffer));
  WT_EXPECT_U64("the maximum is eight bytes", 8U, written);
  WT_EXPECT_BYTES("and is 0xff followed by seven 0xff",
                  (const uint8_t *)"\xff\xff\xff\xff\xff\xff\xff\xff", buffer, 8U);

  /* A buffer too small is refused rather than truncated. */
  WT_EXPECT_U64("one byte will not hold two", 0U, wt_quic_varint_encode(64U, buffer, 1U));
  WT_EXPECT_U64("a NULL buffer is refused", 0U, wt_quic_varint_encode(1U, NULL, 8U));
  WT_EXPECT_U64("an unencodable value is refused", 0U,
                wt_quic_varint_encode(UINT64_C(1) << 62, buffer, sizeof(buffer)));

  /* Decoding, including the RFC's four examples read back. */
  {
    static const struct {
      const char *label;
      uint8_t bytes[8];
      size_t length;
      uint64_t expected;
      size_t expected_size;
    } vectors[] = {
        {"0x25", {0x25U, 0, 0, 0, 0, 0, 0, 0}, 1U, 37U, 1U},
        {"0x7bbd", {0x7bU, 0xbdU, 0, 0, 0, 0, 0, 0}, 2U, 15293U, 2U},
        {"0x9d7f3e7d", {0x9dU, 0x7fU, 0x3eU, 0x7dU, 0, 0, 0, 0}, 4U, 494878333U, 4U},
        {"0xc2197c5eff14e88c",
         {0xc2U, 0x19U, 0x7cU, 0x5eU, 0xffU, 0x14U, 0xe8U, 0x8cU},
         8U,
         UINT64_C(151288809941952652),
         8U},
    };
    size_t i;
    for (i = 0U; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
      c = wt_cursor_init(vectors[i].bytes, vectors[i].length);
      WT_EXPECT_OK(vectors[i].label, wt_quic_varint_decode_sized(&c, &value, &size));
      WT_EXPECT_U64("  value", vectors[i].expected, value);
      WT_EXPECT_U64("  size", (uint64_t)vectors[i].expected_size, (uint64_t)size);
      WT_EXPECT_INT("  and it consumed the whole vector", 1, wt_cursor_at_end(&c));
    }
  }

  /* Truncation at every length: a prefix that claims more bytes than are there
   * is a refusal, and the cursor is left failed rather than half-read. */
  {
    static const uint8_t two_byte_prefix[1] = {0x7bU};
    static const uint8_t four_byte_prefix[3] = {0x9dU, 0x7fU, 0x3eU};
    static const uint8_t eight_byte_prefix[7] = {0xc2U, 0x19U, 0x7cU, 0x5eU, 0xffU, 0x14U, 0xe8U};
    c = wt_cursor_init(two_byte_prefix, sizeof(two_byte_prefix));
    WT_EXPECT_STATUS("a two-byte value with one byte is truncated", WT_ERR_TRUNCATED,
                     wt_quic_varint_decode(&c, &value));
    WT_EXPECT_INT("and the cursor is failed", 1, wt_cursor_failed(&c));
    c = wt_cursor_init(four_byte_prefix, sizeof(four_byte_prefix));
    WT_EXPECT_STATUS("a four-byte value with three bytes is truncated", WT_ERR_TRUNCATED,
                     wt_quic_varint_decode(&c, &value));
    c = wt_cursor_init(eight_byte_prefix, sizeof(eight_byte_prefix));
    WT_EXPECT_STATUS("an eight-byte value with seven bytes is truncated", WT_ERR_TRUNCATED,
                     wt_quic_varint_decode(&c, &value));
    c = wt_cursor_init(NULL, 0U);
    WT_EXPECT_STATUS("an empty cursor is truncated", WT_ERR_TRUNCATED,
                     wt_quic_varint_decode(&c, &value));
  }

  /* RFC 9000 section 16: only the frame type has to be minimally encoded, so a
   * decoder accepts a longer encoding and only the minimality test refuses it. */
  {
    static const uint8_t padded[8] = {0x80U, 0x00U, 0x00U, 0x01U, 0, 0, 0, 0};
    c = wt_cursor_init(padded, 4U);
    WT_EXPECT_OK("a four-byte encoding of 1 decodes",
                 wt_quic_varint_decode_sized(&c, &value, &size));
    WT_EXPECT_U64("as the value 1", 1U, value);
    WT_EXPECT_U64("in four bytes", 4U, size);
    WT_EXPECT_INT("and it is not minimal", 0, wt_quic_varint_is_minimal(value, size));
    WT_EXPECT_INT("while the minimal size of 1 is one byte", 1, wt_quic_varint_is_minimal(1U, 1U));
  }

  /* Every value round-trips through the encoder and decoder, at the boundaries
   * and at a sample in between. */
  {
    static const uint64_t samples[] = {0U,
                                       1U,
                                       63U,
                                       64U,
                                       255U,
                                       16383U,
                                       16384U,
                                       65535U,
                                       1073741823U,
                                       1073741824U,
                                       UINT64_C(0x1234567890ABCDEF),
                                       WT_QUIC_VARINT_MAX};
    size_t i;
    for (i = 0U; i < sizeof(samples) / sizeof(samples[0]); i++) {
      size = wt_quic_varint_size(samples[i]);
      written = wt_quic_varint_encode(samples[i], buffer, sizeof(buffer));
      WT_EXPECT_U64("encoding a sample takes its size", (uint64_t)size, (uint64_t)written);
      c = wt_cursor_init(buffer, written);
      WT_EXPECT_OK("decoding it", wt_quic_varint_decode(&c, &value));
      WT_EXPECT_U64("gives the same value", samples[i], value);
    }
  }

  /* Through a writer, which is how every structure in the library is built: the
   * measuring pass and the writing pass agree on the size. */
  {
    wt_writer_t measure = wt_writer_measure();
    wt_writer_t writer;
    size_t measured = 0U;
    measured = wt_quic_writer_varint(&measure, 494878333U);
    WT_EXPECT_U64("a measured varint is four bytes", 4U, measured);
    WT_EXPECT_U64("and advanced the writer by four", 4U, wt_writer_offset(&measure));
    writer = wt_writer_init(buffer, sizeof(buffer));
    (void)wt_quic_writer_varint(&writer, 494878333U);
    WT_EXPECT_INT("the write succeeded", 1, wt_writer_ok(&writer));
    WT_EXPECT_BYTES("and produced the vector bytes", (const uint8_t *)"\x9d\x7f\x3e\x7d", buffer,
                    4U);
  }

  /* An unencodable value overflows the writer rather than writing a truncated
   * one, and a NULL writer is tolerated: it still reports the length the value
   * occupies, as the header promises for a writer that cannot take the bytes. */
  {
    wt_writer_t writer = wt_writer_init(buffer, sizeof(buffer));
    (void)wt_quic_writer_varint(&writer, UINT64_C(1) << 62);
    WT_EXPECT_INT("an unencodable value overflows the writer", 0, wt_writer_ok(&writer));
    WT_EXPECT_U64("a NULL writer is tolerated", 1U, (uint64_t)wt_quic_writer_varint(NULL, 1U));
  }

  /* NULL arguments. */
  WT_EXPECT_STATUS("a NULL cursor is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_varint_decode(NULL, &value));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_varint_decode(&c, NULL));

  WT_TEST_MAIN_END("wt_quic_varint");
}
