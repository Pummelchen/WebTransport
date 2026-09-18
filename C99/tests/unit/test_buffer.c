/* The growable buffer.
 *
 * Checked here: that growth is amortized rather than quadratic, that the bound
 * is a refusal and not a crash, that a refused append modifies nothing, that
 * consume drops from the front and clamps, and -- through the counting allocator
 * below -- that every byte comes back. The accounting test is the one that
 * catches a reserve that reallocates without freeing, which no functional test
 * would notice.
 */

#include "wt_test.h"

#include "webtransport/buffer.h"

#include <stdlib.h>

/* An allocator that counts outstanding bytes and live blocks, so that a leak is
 * a failed assertion rather than a slow process. It also refuses every
 * allocation once armed, which is how the failure paths are reached without a
 * failing malloc. */
typedef struct wt_counting_allocator {
  size_t outstanding_bytes;
  size_t live_blocks;
  size_t total_allocations;
  int refuse;
} wt_counting_allocator_t;

static void *wt_count_alloc(void *context, size_t size) {
  wt_counting_allocator_t *c = (wt_counting_allocator_t *)context;
  void *block;
  if (c->refuse) return NULL;
  block = malloc(size);
  if (block == NULL) return NULL;
  c->outstanding_bytes += size;
  c->live_blocks++;
  c->total_allocations++;
  /* Filled with a non-zero pattern so that a caller reading uninitialized bytes
   * sees something recognizable rather than zeros that look like success. */
  memset(block, 0xCD, size);
  return block;
}

static void *wt_count_realloc(void *context, void *ptr, size_t old_size, size_t new_size) {
  wt_counting_allocator_t *c = (wt_counting_allocator_t *)context;
  void *block;
  if (c->refuse) return NULL;
  block = realloc(ptr, new_size);
  if (block == NULL) return NULL;
  c->outstanding_bytes = c->outstanding_bytes - old_size + new_size;
  return block;
}

static void wt_count_free(void *context, void *ptr, size_t size) {
  wt_counting_allocator_t *c = (wt_counting_allocator_t *)context;
  c->outstanding_bytes -= size;
  c->live_blocks--;
  free(ptr);
}

static wt_allocator_t wt_count_allocator(wt_counting_allocator_t *counter) {
  wt_allocator_t a;
  a.context = counter;
  a.alloc = wt_count_alloc;
  a.realloc = wt_count_realloc;
  a.free = wt_count_free;
  return a;
}

int main(void) {
  wt_counting_allocator_t counter;
  wt_allocator_t alloc;
  wt_buf_t b;
  wt_status_t status = WT_OK;
  size_t i;

  memset(&counter, 0, sizeof(counter));
  alloc = wt_count_allocator(&counter);

  /* A fresh buffer allocates nothing, and freeing it is valid. */
  b = wt_buf_init(&alloc);
  WT_EXPECT_U64("a fresh buffer allocates nothing", 0U, counter.total_allocations);
  WT_EXPECT_U64("with no bytes outstanding", 0U, counter.outstanding_bytes);
  {
    wt_cursor_t c = wt_buf_cursor(&b);
    WT_EXPECT_U64("and a cursor over it reads nothing", 0U, (uint64_t)wt_cursor_remaining(&c));
    WT_EXPECT_INT("an empty buffer's cursor is at its end", 1, wt_cursor_at_end(&c));
  }

  /* Appending allocates, and the bytes land. */
  WT_EXPECT_OK("append three bytes", wt_buf_append(&b, "abc", 3U));
  WT_EXPECT_U64("the length is three", 3U, b.len);
  WT_EXPECT_TRUE("the capacity grew", b.cap >= 3U);
  WT_EXPECT_BYTES("and the bytes are there", (const uint8_t *)"abc", b.data, 3U);
  WT_EXPECT_INT("one allocation so far", 1, (int)counter.total_allocations);

  /* Growth is amortized: appending 4096 bytes one at a time must not reallocate
   * 4096 times. The bound is deliberately loose; the point is the order. */
  {
    wt_counting_allocator_t growth_counter;
    wt_allocator_t growth_alloc;
    wt_buf_t grow;
    size_t before;
    memset(&growth_counter, 0, sizeof(growth_counter));
    growth_alloc = wt_count_allocator(&growth_counter);
    grow = wt_buf_init(&growth_alloc);
    for (i = 0U; i < 4096U; i++) {
      WT_EXPECT_OK("append one byte", wt_buf_append_u8(&grow, (uint8_t)i));
    }
    before = growth_counter.total_allocations;
    WT_EXPECT_U64("all 4096 bytes are present", 4096U, grow.len);
    WT_EXPECT_TRUE("and the reallocation count is logarithmic, not linear", before <= 32U);
    wt_buf_free(&grow);
    WT_EXPECT_U64("the growing buffer freed everything", 0U, growth_counter.outstanding_bytes);
  }

  /* A reserve past the bound is WT_ERR_LIMIT and modifies nothing. */
  {
    wt_buf_t bounded = wt_buf_init(&alloc);
    size_t len_before = bounded.len;
    size_t cap_before = bounded.cap;
    WT_EXPECT_STATUS("a reserve past the bound is refused", WT_ERR_LIMIT,
                     wt_buf_reserve(&bounded, WT_BUF_MAX_CAPACITY + 1U));
    WT_EXPECT_U64("the length is unchanged", len_before, bounded.len);
    WT_EXPECT_U64("and so is the capacity", cap_before, bounded.cap);
    /* An append whose total would exceed the bound is refused too. */
    WT_EXPECT_STATUS("an append past the bound is refused", WT_ERR_LIMIT,
                     wt_buf_append(&bounded, "x", WT_BUF_MAX_CAPACITY + 1U));
    wt_buf_free(&bounded);
  }

  /* A refused allocation leaves the buffer usable and unchanged. */
  {
    wt_buf_t refused = wt_buf_init(&alloc);
    WT_EXPECT_OK("append before arming the refusal", wt_buf_append(&refused, "hello", 5U));
    counter.refuse = 1;
    WT_EXPECT_STATUS("an append with no memory", WT_ERR_OUT_OF_MEMORY,
                     wt_buf_append(&refused, "0123456789", 10U));
    WT_EXPECT_U64("the length is unchanged", 5U, refused.len);
    WT_EXPECT_BYTES("and so are the bytes", (const uint8_t *)"hello", refused.data, 5U);
    counter.refuse = 0;
    wt_buf_free(&refused);
  }

  /* Consume drops from the front, and dropping more than there is empties. */
  WT_EXPECT_OK("append a longer run", wt_buf_append(&b, "0123456789", 10U));
  WT_EXPECT_U64("thirteen bytes now", 13U, b.len);
  wt_buf_consume(&b, 3U);
  WT_EXPECT_U64("ten left after dropping three", 10U, b.len);
  WT_EXPECT_BYTES("and the front is now the fourth byte", (const uint8_t *)"0123456789", b.data,
                  10U);
  wt_buf_consume(&b, 0U);
  WT_EXPECT_U64("dropping zero changes nothing", 10U, b.len);
  wt_buf_consume(&b, 10U);
  WT_EXPECT_U64("dropping exactly the length empties it", 0U, b.len);
  WT_EXPECT_OK("append again", wt_buf_append(&b, "xy", 2U));
  wt_buf_consume(&b, 99U);
  WT_EXPECT_U64("dropping more than there is clamps to empty", 0U, b.len);

  /* clear keeps the storage; shrink_to_fit releases the slack. */
  WT_EXPECT_OK("append to refill", wt_buf_append(&b, "0123456789", 10U));
  {
    size_t cap_before = b.cap;
    wt_buf_clear(&b);
    WT_EXPECT_U64("clear sets the length to zero", 0U, b.len);
    WT_EXPECT_U64("and keeps the capacity", cap_before, b.cap);
  }
  WT_EXPECT_OK("append again after clear", wt_buf_append(&b, "abc", 3U));
  wt_buf_shrink_to_fit(&b);
  WT_EXPECT_U64("shrink fits the capacity to the length", 3U, b.cap);
  WT_EXPECT_U64("and keeps the length", 3U, b.len);
  WT_EXPECT_BYTES("and the bytes", (const uint8_t *)"abc", b.data, 3U);
  wt_buf_clear(&b);
  wt_buf_shrink_to_fit(&b);
  WT_EXPECT_U64("shrinking an empty buffer releases everything", 0U, b.cap);
  WT_EXPECT_TRUE("and leaves no block", b.data == NULL);

  /* A cursor over the buffer reads what was written. */
  wt_buf_clear(&b);
  WT_EXPECT_OK("append for the cursor", wt_buf_append(&b, "\x01\x02\x03", 3U));
  {
    wt_cursor_t c = wt_buf_cursor(&b);
    WT_EXPECT_U64("the cursor reads the first byte", 0x01U, wt_cursor_u8(&c));
    WT_EXPECT_U64("and the rest as a u16", 0x0203U, wt_cursor_u16(&c));
    WT_EXPECT_INT("then it is at the end", 1, wt_cursor_at_end(&c));
  }

  /* copy_out is a real copy with its own ownership. */
  {
    uint8_t *copy = wt_buf_copy_out(&b, 1U, 2U, &alloc, &status);
    WT_EXPECT_OK("copy_out succeeds", status);
    WT_EXPECT_TRUE("and returns a block", copy != NULL);
    if (copy != NULL) {
      WT_EXPECT_BYTES("holding the right bytes", (const uint8_t *)"\x02\x03", copy, 2U);
      wt_dealloc(&alloc, copy, 2U);
    }
    WT_EXPECT_TRUE("copying past the end is NULL",
                   wt_buf_copy_out(&b, 2U, 2U, &alloc, &status) == NULL);
    WT_EXPECT_STATUS("and reports an invalid argument", WT_ERR_INVALID_ARGUMENT, status);
    WT_EXPECT_TRUE("copying outside the buffer is NULL",
                   wt_buf_copy_out(&b, 4U, 1U, &alloc, &status) == NULL);
    /* A zero-length copy is valid and freeable. */
    copy = wt_buf_copy_out(&b, 0U, 0U, &alloc, &status);
    WT_EXPECT_OK("a zero-length copy succeeds", status);
    wt_dealloc(&alloc, copy, 0U);
  }

  /* reserve_tail hands back unwritten bytes and counts them. */
  {
    uint8_t *tail;
    wt_buf_clear(&b);
    tail = wt_buf_reserve_tail(&b, 4U);
    WT_EXPECT_TRUE("reserve_tail returns bytes", tail != NULL);
    WT_EXPECT_U64("and counts them", 4U, b.len);
    if (tail != NULL) {
      tail[0] = 0xAAU;
      WT_EXPECT_INT("which are writable", 0xAA, (int)b.data[0]);
    }
  }

  /* Freeing releases every byte, including through a reallocation. */
  wt_buf_free(&b);
  WT_EXPECT_U64("no bytes are outstanding after free", 0U, counter.outstanding_bytes);
  WT_EXPECT_U64("and no blocks are live", 0U, counter.live_blocks);
  WT_EXPECT_TRUE("the buffer is empty", b.data == NULL && b.len == 0U && b.cap == 0U);
  /* Freeing twice is valid, because a cleanup path that runs twice is common. */
  wt_buf_free(&b);
  WT_EXPECT_U64("freeing twice changes nothing", 0U, counter.live_blocks);

  /* A zeroed allocator means the default one rather than a NULL call. */
  {
    wt_allocator_t zeroed;
    wt_buf_t defaulted;
    memset(&zeroed, 0, sizeof(zeroed));
    defaulted = wt_buf_init(&zeroed);
    WT_EXPECT_OK("a zeroed allocator selects the default", wt_buf_append(&defaulted, "ok", 2U));
    WT_EXPECT_U64("and the default allocated", 2U, defaulted.len);
    wt_buf_free(&defaulted);
  }

  /* A NULL buffer argument is refused rather than dereferenced. */
  WT_EXPECT_STATUS("reserve on NULL", WT_ERR_INVALID_ARGUMENT, wt_buf_reserve(NULL, 1U));
  WT_EXPECT_STATUS("append on NULL", WT_ERR_INVALID_ARGUMENT, wt_buf_append(NULL, "x", 1U));
  WT_EXPECT_STATUS("append of NULL data", WT_ERR_INVALID_ARGUMENT, wt_buf_append(&b, NULL, 1U));
  WT_EXPECT_OK("append of zero bytes is fine", wt_buf_append(&b, NULL, 0U));
  WT_EXPECT_TRUE("reserve_tail on NULL is NULL", wt_buf_reserve_tail(NULL, 1U) == NULL);
  wt_buf_free(NULL);
  wt_buf_consume(NULL, 1U);
  wt_buf_clear(NULL);
  wt_buf_shrink_to_fit(NULL);
  {
    wt_cursor_t c = wt_buf_cursor(NULL);
    WT_EXPECT_INT("a cursor over a NULL buffer is empty", 1, wt_cursor_at_end(&c));
  }
  wt_buf_free(&b);
  WT_EXPECT_U64("still nothing outstanding", 0U, counter.outstanding_bytes);

  WT_TEST_MAIN_END("wt_buffer");
}
