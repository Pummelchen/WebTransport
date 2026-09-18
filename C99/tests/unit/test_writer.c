/* The two-pass writer.
 *
 * The property that makes the writer worth having is that measuring and writing
 * agree. So the central test builds the same structure twice -- once into a
 * measurement, once into a buffer sized from that measurement -- and requires
 * the two to be the same length and the buffer to be exactly filled. A second
 * buffer one byte too small must overflow rather than be written past, which is
 * checked by putting a guard byte after it and asserting the guard is intact.
 */

#include "wt_test.h"

#include "webtransport/endian.h"
#include "webtransport/writer.h"

/* The structure both modes build: a one-byte count, that many two-byte values,
 * and a three-byte length prefix. Enough nesting to catch an offset that is
 * counted twice. */
static void wt_write_sample(wt_writer_t *w, const uint16_t *values, size_t count) {
  size_t i;
  size_t at = wt_writer_offset(w);
  wt_writer_u24(w, 0U); /* reserved, patched below */
  wt_writer_u8(w, (uint8_t)count);
  for (i = 0U; i < count; i++)
    wt_writer_u16(w, values[i]);
  /* A measuring writer has nowhere to patch, and does not need to: the
   * reserved three bytes were counted, so the measurement is already right. The
   * pattern is to write the prefix only when there is a destination, which is
   * what `wt_writer_is_measuring` is for. */
  if (!wt_writer_is_measuring(w)) {
    size_t body = wt_writer_offset(w) - at - 3U;
    uint8_t prefix[3];
    wt_store_be24(prefix, (uint32_t)body);
    /* The status is deliberately not asserted here: this function is called
     * with an under-sized buffer on purpose, and the patch must then refuse
     * like every other write. What the caller checks is wt_writer_ok and the
     * bytes. */
    (void)wt_writer_patch(w, at, prefix, sizeof(prefix));
  }
}

int main(void) {
  static const uint16_t values[3] = {0x0102U, 0x0304U, 0x0506U};
  /* Three bytes of length prefix, one byte of count, three two-byte values.
   * The prefix counts the seven bytes after it. */
  static const uint8_t expected[10] = {0x00U, 0x00U, 0x07U, 0x03U, 0x01U,
                                       0x02U, 0x03U, 0x04U, 0x05U, 0x06U};
  uint8_t buffer[32];
  wt_writer_t measure;
  wt_writer_t writing;
  size_t measured = 0U;

  /* Measuring mode counts and does not need a destination. */
  measure = wt_writer_measure();
  WT_EXPECT_INT("a measuring writer says so", 1, wt_writer_is_measuring(&measure));
  wt_write_sample(&measure, values, 3U);
  WT_EXPECT_INT("the measurement did not overflow", 1, wt_writer_ok(&measure));
  measured = wt_writer_offset(&measure);
  WT_EXPECT_U64("the measurement is ten bytes", (uint64_t)sizeof(expected), measured);

  /* Writing mode produces exactly the measured bytes. */
  memset(buffer, 0, sizeof(buffer));
  writing = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_INT("a writing writer does not measure", 0, wt_writer_is_measuring(&writing));
  wt_write_sample(&writing, values, 3U);
  WT_EXPECT_INT("the write did not overflow", 1, wt_writer_ok(&writing));
  WT_EXPECT_U64("and wrote the measured count", measured, wt_writer_offset(&writing));
  WT_EXPECT_BYTES("and the measured bytes", expected, buffer, measured);

  /* The caller sizes from the measurement and the encoder refuses if it was
   * wrong: a buffer one byte short overflows and is not written past. */
  memset(buffer, 0xAA, sizeof(buffer));
  writing = wt_writer_init(buffer, measured - 1U);
  wt_write_sample(&writing, values, 3U);
  WT_EXPECT_INT("a short buffer overflows", 0, wt_writer_ok(&writing));
  WT_EXPECT_INT("the guard byte after the short buffer is untouched", 0xAA,
                (int)buffer[measured - 1U]);

  /* An exactly-sized buffer succeeds and the byte after it is untouched. */
  memset(buffer, 0xAA, sizeof(buffer));
  writing = wt_writer_init(buffer, measured);
  wt_write_sample(&writing, values, 3U);
  WT_EXPECT_INT("an exactly-sized buffer succeeds", 1, wt_writer_ok(&writing));
  WT_EXPECT_INT("the byte after it is untouched", 0xAA, (int)buffer[measured]);

  /* Zero-length writes are valid at the end of a full buffer. */
  writing = wt_writer_init(buffer, measured);
  wt_writer_bytes(&writing, NULL, 0U);
  WT_EXPECT_INT("a full buffer accepts a zero-length write", 1, wt_writer_ok(&writing));
  WT_EXPECT_U64("and did not move", 0U, wt_writer_offset(&writing));

  /* Scalar encodings are big-endian and the widths are the documented ones. */
  memset(buffer, 0, sizeof(buffer));
  writing = wt_writer_init(buffer, sizeof(buffer));
  wt_writer_u8(&writing, 0x11U);
  wt_writer_u16(&writing, 0x2233U);
  wt_writer_u24(&writing, 0x445566U);
  wt_writer_u32(&writing, 0x778899AAU);
  wt_writer_u64(&writing, UINT64_C(0xBBCCDDEEFF001122));
  WT_EXPECT_U64("the scalar writes are 18 bytes", 18U, wt_writer_offset(&writing));
  WT_EXPECT_BYTES("their bytes are big-endian",
                  (const uint8_t *)"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
                                   "\xbb\xcc\xdd\xee\xff\x00\x11\x22",
                  buffer, 18U);

  /* reserve hands back writable bytes and advances the position. */
  memset(buffer, 0, sizeof(buffer));
  writing = wt_writer_init(buffer, sizeof(buffer));
  {
    uint8_t *at = wt_writer_reserve(&writing, 4U);
    WT_EXPECT_TRUE("reserve returns the bytes", at != NULL);
    if (at != NULL) {
      at[0] = 0xDEU;
      at[3] = 0xADU;
    }
    WT_EXPECT_U64("reserve advanced the position", 4U, wt_writer_offset(&writing));
    WT_EXPECT_TRUE("reserve of more than fits is NULL",
                   wt_writer_reserve(&writing, sizeof(buffer)) == NULL);
    WT_EXPECT_INT("and it overflowed the writer", 0, wt_writer_ok(&writing));
    (void)at;
  }

  /* A measuring writer has no bytes to hand back, and reserve says so rather
   * than returning a pointer into nothing. */
  measure = wt_writer_measure();
  WT_EXPECT_TRUE("reserve on a measurement is NULL", wt_writer_reserve(&measure, 4U) == NULL);
  WT_EXPECT_U64("but the measurement still advanced", 4U, wt_writer_offset(&measure));

  /* Patching only reaches region that was actually written. */
  writing = wt_writer_init(buffer, sizeof(buffer));
  wt_writer_u8(&writing, 0x01U);
  WT_EXPECT_STATUS("a patch inside the written region", WT_OK,
                   wt_writer_patch(&writing, 0U, "\x02", 1U));
  WT_EXPECT_INT("and it landed", 0x02, (int)buffer[0]);
  WT_EXPECT_STATUS("a patch past the written region is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_writer_patch(&writing, 1U, "\x03", 1U));
  WT_EXPECT_STATUS("a patch that overruns it is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_writer_patch(&writing, 0U, "\x03\x04", 2U));
  WT_EXPECT_STATUS("a patch of a NULL cursor is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_writer_patch(NULL, 0U, "\x01", 1U));
  WT_EXPECT_STATUS("a patch of NULL data is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_writer_patch(&writing, 0U, NULL, 1U));
  measure = wt_writer_measure();
  WT_EXPECT_STATUS("a patch of a measurement is refused", WT_ERR_LIMIT,
                   wt_writer_patch(&measure, 0U, "\x01", 1U));

  /* A NULL-destination writer with a non-zero capacity is a caller error and
   * reports itself as overflowing rather than counting into nothing. */
  writing = wt_writer_init(NULL, 8U);
  WT_EXPECT_INT("a NULL destination with a capacity is not ok", 0, wt_writer_ok(&writing));
  writing = wt_writer_init(NULL, 0U);
  WT_EXPECT_INT("a NULL destination with no capacity is ok", 1, wt_writer_ok(&writing));

  WT_TEST_MAIN_END("wt_writer");
}
