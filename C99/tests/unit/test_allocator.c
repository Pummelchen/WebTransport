/* The allocator interface.
 *
 * The cases: the default allocator works and hands back memory aligned for any
 * type, a zero-size request yields a unique freeable pointer rather than NULL so
 * that NULL always means failure, the array helpers check their multiplication,
 * and a zeroed or partially filled allocator falls back to the default instead
 * of calling through a NULL function pointer.
 */

#include "wt_test.h"

#include "webtransport/allocator.h"

#include <stdlib.h>

typedef struct wt_probe {
  size_t allocations;
  size_t frees;
  size_t last_size;
  size_t last_old_size;
  int refuse;
} wt_probe_t;

static void *wt_probe_alloc(void *context, size_t size) {
  wt_probe_t *p = (wt_probe_t *)context;
  p->allocations++;
  p->last_size = size;
  if (p->refuse) return NULL;
  return malloc(size);
}

static void *wt_probe_realloc(void *context, void *ptr, size_t old_size, size_t new_size) {
  wt_probe_t *p = (wt_probe_t *)context;
  p->last_old_size = old_size;
  p->last_size = new_size;
  if (p->refuse) return NULL;
  return realloc(ptr, new_size);
}

static void wt_probe_free(void *context, void *ptr, size_t size) {
  wt_probe_t *p = (wt_probe_t *)context;
  p->frees++;
  p->last_size = size;
  free(ptr);
}

int main(void) {
  wt_allocator_t def = wt_allocator_default();
  wt_status_t status = WT_OK;
  void *block = NULL;

  /* The default allocator is complete. */
  WT_EXPECT_TRUE("the default allocator has an alloc", def.alloc != NULL);
  WT_EXPECT_TRUE("the default allocator has a realloc", def.realloc != NULL);
  WT_EXPECT_TRUE("the default allocator has a free", def.free != NULL);
  WT_EXPECT_TRUE("the default allocator has no context", def.context == NULL);

  /* Allocation, writing, resizing and releasing through it. */
  block = wt_alloc(&def, 16U);
  WT_EXPECT_TRUE("a 16-byte allocation succeeds", block != NULL);
  if (block != NULL) {
    memset(block, 0x5A, 16U);
    /* Alignment for any type is a promise the interface makes, so it is checked
     * where a misaligned block would be a crash on a strict platform. */
    WT_EXPECT_U64("the block is aligned for a pointer", 0U,
                  (uint64_t)((uintptr_t)block % sizeof(void *)));
    block = wt_realloc(&def, block, 16U, 64U);
    WT_EXPECT_TRUE("growing it succeeds", block != NULL);
    if (block != NULL) {
      WT_EXPECT_INT("the contents survived the growth", 0x5A, (int)((uint8_t *)block)[0]);
      wt_dealloc(&def, block, 64U);
    }
  }

  /* A zero-size request is a unique, freeable pointer and never NULL. */
  {
    void *a = wt_alloc(&def, 0U);
    void *b = wt_alloc(&def, 0U);
    WT_EXPECT_TRUE("a zero-size allocation is not NULL", a != NULL);
    WT_EXPECT_TRUE("and two of them are distinct", a != b);
    wt_dealloc(&def, a, 0U);
    wt_dealloc(&def, b, 0U);
  }

  /* Freeing NULL is a documented no-op; it is checked through the probe below,
   * where a counting free callback can show whether it was reached at all. */

  /* Reallocating a NULL block allocates. */
  block = wt_realloc(&def, NULL, 0U, 8U);
  WT_EXPECT_TRUE("realloc of NULL allocates", block != NULL);
  wt_dealloc(&def, block, 8U);

  /* The array helpers multiply with a check. */
  block = wt_alloc_array(&def, 4U, 8U, &status);
  WT_EXPECT_OK("an array of four eight-byte elements", status);
  WT_EXPECT_TRUE("and it is allocated", block != NULL);
  wt_dealloc(&def, block, 32U);

  block = wt_calloc_array(&def, 4U, 8U, &status);
  WT_EXPECT_OK("a zeroed array", status);
  WT_EXPECT_TRUE("and it is allocated", block != NULL);
  if (block != NULL) {
    static const uint8_t zeroes[32] = {0};
    WT_EXPECT_BYTES("and it is all zeros", zeroes, (const uint8_t *)block, 32U);
    wt_dealloc(&def, block, 32U);
  }

  /* The multiplication is refused before anything is allocated, so a count from
   * the wire cannot wrap into a small allocation. */
  block = wt_alloc_array(&def, SIZE_MAX, 2U, &status);
  WT_EXPECT_TRUE("an array whose size wraps is refused", block == NULL);
  WT_EXPECT_STATUS("and reports an overflow", WT_ERR_OVERFLOW, status);
  block = wt_calloc_array(&def, SIZE_MAX, 2U, &status);
  WT_EXPECT_TRUE("the zeroed form refuses it too", block == NULL);
  WT_EXPECT_STATUS("and reports an overflow", WT_ERR_OVERFLOW, status);

  /* A NULL status out-parameter is allowed; the NULL block is the answer. */
  block = wt_alloc_array(&def, SIZE_MAX, 2U, NULL);
  WT_EXPECT_TRUE("a refused array with no status is still NULL", block == NULL);

  /* A failing allocator reports out-of-memory from the zeroed helper, which is
   * the only place the library distinguishes it from a refused limit. */
  {
    wt_probe_t probe;
    wt_allocator_t a;
    memset(&probe, 0, sizeof(probe));
    a.context = &probe;
    a.alloc = wt_probe_alloc;
    a.realloc = wt_probe_realloc;
    a.free = wt_probe_free;

    probe.refuse = 1;
    block = wt_calloc_array(&a, 1U, 4U, &status);
    WT_EXPECT_TRUE("a refused allocation is NULL", block == NULL);
    WT_EXPECT_STATUS("and reports out of memory", WT_ERR_OUT_OF_MEMORY, status);

    probe.refuse = 0;

    /* Freeing NULL is a no-op: it must not reach the allocator's callback. */
    wt_dealloc(&a, NULL, 0U);
    WT_EXPECT_U64("freeing NULL never reaches the allocator", 0U, probe.frees);

    /* Every block that is allocated here is released here. An earlier version
     * of this file allocated one inside a WT_EXPECT_TRUE and never freed it,
     * which LeakSanitizer on the Linux CI leg reported as "8 byte(s) leaked in
     * 2 allocation(s)" -- a defect in the test rather than in the library, and
     * one that only a sanitizer that runs at exit can see, since the process
     * had already passed every assertion. */
    block = wt_alloc(NULL, 4U);
    WT_EXPECT_TRUE("a NULL allocator selects the default", block != NULL);
    wt_dealloc(NULL, block, 4U);

    /* A partially filled allocator is a caller's bug, and the safe reading of
     * it is "use the default" rather than a call through a NULL pointer. */
    {
      wt_allocator_t partial;
      size_t before = probe.allocations;
      memset(&partial, 0, sizeof(partial));
      partial.alloc = wt_probe_alloc;
      block = wt_alloc(&partial, 4U);
      WT_EXPECT_TRUE("a partial allocator falls back to the default", block != NULL);
      wt_dealloc(&partial, block, 4U);
      WT_EXPECT_U64("and never reached the probe", before, probe.allocations);
    }

    /* The size handed to free is the size that was requested, which is what a
     * counting allocator needs to be exact. */
    block = wt_alloc(&a, 24U);
    WT_EXPECT_U64("the probe saw the requested size", 24U, probe.last_size);
    wt_dealloc(&a, block, 24U);
    WT_EXPECT_U64("and free saw the same size", 24U, probe.last_size);
    WT_EXPECT_U64("with one free recorded", 1U, probe.frees);
  }

  WT_TEST_MAIN_END("wt_allocator");
}
