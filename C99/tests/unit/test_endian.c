/* Big-endian load and store.
 *
 * Two properties are checked: that a store produces the exact bytes the wire
 * format requires -- the RFC's own byte order, not this machine's -- and that a
 * load of those bytes returns the value. Both directions are checked against a
 * literal byte array rather than against each other, because a load and a store
 * that were wrong in the same way would round-trip perfectly.
 */

#include "wt_test.h"

#include "webtransport/endian.h"

int main(void) {
  static const uint8_t be16[2] = {0x12U, 0x34U};
  static const uint8_t be24[3] = {0x12U, 0x34U, 0x56U};
  static const uint8_t be32[4] = {0x12U, 0x34U, 0x56U, 0x78U};
  static const uint8_t be64[8] = {0x01U, 0x23U, 0x45U, 0x67U,
                                  0x89U, 0xABU, 0xCDU, 0xEFU};
  uint8_t out[8];

  WT_EXPECT_U64("be16 loads big-endian", 0x1234U, wt_load_be16(be16));
  WT_EXPECT_U64("be24 loads big-endian", 0x123456U, wt_load_be24(be24));
  WT_EXPECT_U64("be32 loads big-endian", 0x12345678U, wt_load_be32(be32));
  WT_EXPECT_U64("be64 loads big-endian", UINT64_C(0x0123456789ABCDEF),
                wt_load_be64(be64));

  /* The high byte first, whatever this machine's byte order is. */
  memset(out, 0, sizeof(out));
  wt_store_be16(out, 0x1234U);
  WT_EXPECT_BYTES("be16 stores 12 34", be16, out, 2U);
  memset(out, 0, sizeof(out));
  wt_store_be24(out, 0x123456U);
  WT_EXPECT_BYTES("be24 stores 12 34 56", be24, out, 3U);
  memset(out, 0, sizeof(out));
  wt_store_be32(out, 0x12345678U);
  WT_EXPECT_BYTES("be32 stores 12 34 56 78", be32, out, 4U);
  memset(out, 0, sizeof(out));
  wt_store_be64(out, UINT64_C(0x0123456789ABCDEF));
  WT_EXPECT_BYTES("be64 stores 01 23 45 67 89 ab cd ef", be64, out, 8U);

  /* The boundaries: zero, one, and the all-ones value of each width. A store
   * that masked the wrong bits shows up here and nowhere else. */
  wt_store_be24(out, 0U);
  WT_EXPECT_U64("be24 of zero", 0U, wt_load_be24(out));
  wt_store_be24(out, 0xFFFFFFU);
  WT_EXPECT_BYTES("be24 of all ones", (const uint8_t *)"\xff\xff\xff", out, 3U);
  wt_store_be32(out, 0U);
  WT_EXPECT_U64("be32 of zero", 0U, wt_load_be32(out));
  wt_store_be32(out, UINT32_MAX);
  WT_EXPECT_BYTES("be32 of all ones", (const uint8_t *)"\xff\xff\xff\xff", out,
                  4U);
  wt_store_be64(out, 0U);
  WT_EXPECT_U64("be64 of zero", 0U, wt_load_be64(out));
  wt_store_be64(out, UINT64_MAX);
  WT_EXPECT_BYTES("be64 of all ones",
                  (const uint8_t *)"\xff\xff\xff\xff\xff\xff\xff\xff", out, 8U);

  /* The widths the header documents, since a caller sizes a buffer from them. */
  WT_EXPECT_U64("WT_BE16_SIZE", 2U, WT_BE16_SIZE);
  WT_EXPECT_U64("WT_BE24_SIZE", 3U, WT_BE24_SIZE);
  WT_EXPECT_U64("WT_BE32_SIZE", 4U, WT_BE32_SIZE);
  WT_EXPECT_U64("WT_BE64_SIZE", 8U, WT_BE64_SIZE);

  /* Load and store agree as well, for a value that is not a round number. */
  wt_store_be32(out, 0xDEADBEEFU);
  WT_EXPECT_U64("be32 round trip", 0xDEADBEEFU, wt_load_be32(out));

  WT_TEST_MAIN_END("wt_endian");
}
