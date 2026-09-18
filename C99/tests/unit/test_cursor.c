/* The read cursor.
 *
 * The important cases are the negative ones. A cursor that reads past its end
 * must fail rather than return whatever is in memory next, the failure must
 * stick so that a parser which checks once at the end is still correct, and the
 * offset must not move on a failed read so that a caller which retries after
 * more bytes arrive retries from the same place.
 */

#include "wt_test.h"

#include "webtransport/cursor.h"

int main(void) {
  static const uint8_t bytes[8] = {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U};
  wt_cursor_t c;
  size_t len = 0U;
  const uint8_t *p;

  /* An empty cursor is valid, and an at-end empty cursor is not a failure. */
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_INT("an empty cursor is at its end", 1, wt_cursor_at_end(&c));
  WT_EXPECT_INT("an empty cursor has not failed", 0, wt_cursor_failed(&c));
  WT_EXPECT_U64("an empty cursor has nothing left", 0U, wt_cursor_remaining(&c));
  WT_EXPECT_TRUE("the remaining view of an empty cursor is NULL", wt_cursor_rest(&c, &len) == NULL);
  WT_EXPECT_U64("and its length is zero", 0U, len);

  /* A NULL data pointer with a non-zero length is not a range: the cursor
   * treats it as empty rather than as a pointer into nothing. */
  c = wt_cursor_init(NULL, 8U);
  WT_EXPECT_INT("a NULL range is empty", 1, wt_cursor_at_end(&c));
  WT_EXPECT_U64("a NULL range has nothing left", 0U, wt_cursor_remaining(&c));

  /* Sequential reads in wire order. */
  c = wt_cursor_init(bytes, sizeof(bytes));
  WT_EXPECT_U64("eight bytes remain", 8U, wt_cursor_remaining(&c));
  WT_EXPECT_U64("u8", 0x01U, wt_cursor_u8(&c));
  WT_EXPECT_U64("u16 is big-endian", 0x0203U, wt_cursor_u16(&c));
  WT_EXPECT_U64("u24 is big-endian", 0x040506U, wt_cursor_u24(&c));
  WT_EXPECT_U64("u8 again", 0x07U, wt_cursor_u8(&c));
  WT_EXPECT_U64("one byte remains", 1U, wt_cursor_remaining(&c));
  WT_EXPECT_INT("not at the end yet", 0, wt_cursor_at_end(&c));
  WT_EXPECT_U64("and the last byte", 0x08U, wt_cursor_u8(&c));
  WT_EXPECT_INT("now at the end", 1, wt_cursor_at_end(&c));
  WT_EXPECT_INT("and not failed", 0, wt_cursor_failed(&c));

  /* Reading past the end fails and leaves the cursor where it was. */
  c = wt_cursor_init(bytes, sizeof(bytes));
  WT_EXPECT_U64("consume two", 0x0102U, wt_cursor_u16(&c));
  WT_EXPECT_TRUE("bytes(8) of 6 remaining is NULL", wt_cursor_bytes(&c, 8U) == NULL);
  WT_EXPECT_INT("the failure sticks", 1, wt_cursor_failed(&c));
  WT_EXPECT_U64("a failed cursor reports nothing remaining", 0U, wt_cursor_remaining(&c));
  WT_EXPECT_INT("a failed cursor is not at its end", 0, wt_cursor_at_end(&c));
  /* Every later read is a no-op returning zero rather than a second failure
   * with a different meaning. */
  WT_EXPECT_U64("a read after failure", 0U, wt_cursor_u8(&c));
  WT_EXPECT_U64("another read after failure", 0U, wt_cursor_u32(&c));

  /* A partial read at the boundary: six bytes left, a u64 does not fit. */
  c = wt_cursor_init(bytes, sizeof(bytes));
  WT_EXPECT_U64("consume two", 0x0102U, wt_cursor_u16(&c));
  WT_EXPECT_U64("a u64 of six bytes left", 0U, wt_cursor_u64(&c));
  WT_EXPECT_INT("and it failed", 1, wt_cursor_failed(&c));

  /* Exactly enough: a u32 of the last four bytes succeeds. */
  c = wt_cursor_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("skip four", wt_cursor_skip(&c, 4U));
  WT_EXPECT_U64("the last u32", 0x05060708U, wt_cursor_u32(&c));
  WT_EXPECT_INT("at the end", 1, wt_cursor_at_end(&c));
  WT_EXPECT_INT("no failure", 0, wt_cursor_failed(&c));

  /* Skipping past the end is a status, not a silent no-op. */
  c = wt_cursor_init(bytes, sizeof(bytes));
  WT_EXPECT_STATUS("skipping past the end is truncated", WT_ERR_TRUNCATED, wt_cursor_skip(&c, 9U));
  /* The cursor is unusable after a failed read -- that is the point of the
   * sticky flag, since a caller that carried on would be parsing a message it
   * had already rejected. Skipping exactly to the end therefore needs a fresh
   * cursor. */
  WT_EXPECT_STATUS("a failed cursor refuses to skip", WT_ERR_TRUNCATED, wt_cursor_skip(&c, 8U));
  c = wt_cursor_init(bytes, sizeof(bytes));
  WT_EXPECT_STATUS("skipping exactly to the end", WT_OK, wt_cursor_skip(&c, 8U));
  WT_EXPECT_STATUS("skipping zero is fine", WT_OK, wt_cursor_skip(&c, 0U));
  WT_EXPECT_STATUS("skipping a NULL cursor is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_cursor_skip(NULL, 1U));

  /* A zero-length view is a valid view: the pointer is inside the range, which
   * is what lets a length-delimited sub-parser be handed an empty region. */
  c = wt_cursor_init(bytes, sizeof(bytes));
  p = wt_cursor_bytes(&c, 0U);
  WT_EXPECT_TRUE("a zero-length view is not NULL", p != NULL);
  WT_EXPECT_TRUE("and it points at the current position", p == bytes);

  /* The remaining view hands a sub-parser exactly the rest. */
  c = wt_cursor_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("skip one", wt_cursor_skip(&c, 1U));
  p = wt_cursor_rest(&c, &len);
  WT_EXPECT_U64("seven bytes remain", 7U, len);
  WT_EXPECT_BYTES("and they are the last seven", bytes + 1, p, 7U);

  /* NULL cursors do not crash. A caller reaches these from an error path. */
  WT_EXPECT_U64("u8 of a NULL cursor", 0U, wt_cursor_u8(NULL));
  WT_EXPECT_INT("at_end of a NULL cursor", 0, wt_cursor_at_end(NULL));
  WT_EXPECT_INT("failed of a NULL cursor", 1, wt_cursor_failed(NULL));
  WT_EXPECT_U64("remaining of a NULL cursor", 0U, wt_cursor_remaining(NULL));
  WT_EXPECT_TRUE("rest of a NULL cursor is NULL", wt_cursor_rest(NULL, &len) == NULL);

  WT_TEST_MAIN_END("wt_cursor");
}
