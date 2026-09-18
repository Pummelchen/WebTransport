/* QPACK's dynamic table (RFC 9204 section 3.2).
 *
 * The table is peer-driven state with an index that must never change meaning, so
 * the tests are about the arithmetic across evictions rather than about a single
 * insert: the absolute index of every live entry, what happens to the indices when
 * entries are evicted, the size rule (name and value plus 32) that decides when
 * eviction starts, an entry larger than the capacity being refused rather than
 * truncated, and a capacity that shrinks emptying the table. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static size_t entry_size(size_t name_length, size_t value_length) {
  return name_length + value_length + (size_t)WT_QPACK_DYNAMIC_ENTRY_OVERHEAD;
}

static void test_insert_and_lookup(void) {
  wt_qpack_dynamic_table_t table;
  uint64_t index = 0U;
  const uint8_t *name = NULL;
  const uint8_t *value = NULL;
  size_t name_length = 0U;
  size_t value_length = 0U;

  wt_qpack_dynamic_init(&table, 4096U);
  WT_EXPECT_U64("an empty table has no entries", 0U, (uint64_t)table.count);
  WT_EXPECT_U64("and no insertions", 0U, table.insert_count);

  WT_EXPECT_OK("an entry inserts", wt_qpack_dynamic_insert(&table, (const uint8_t *)"x-a", 3U,
                                                           (const uint8_t *)"one", 3U, &index));
  WT_EXPECT_U64("at absolute index zero", 0U, index);
  WT_EXPECT_OK("and another", wt_qpack_dynamic_insert(&table, (const uint8_t *)"x-b", 3U,
                                                      (const uint8_t *)"two", 3U, &index));
  WT_EXPECT_U64("at absolute index one", 1U, index);
  WT_EXPECT_U64("which the table counts", 2U, table.insert_count);
  WT_EXPECT_U64("and sizes by the section's rule", (uint64_t)(2U * entry_size(3U, 3U)),
                (uint64_t)table.size);

  WT_EXPECT_OK("the first entry reads back",
               wt_qpack_dynamic_entry(&table, 0U, &name, &name_length, &value, &value_length));
  WT_EXPECT_BYTES("with its name", (const uint8_t *)"x-a", name, 3U);
  WT_EXPECT_BYTES("and its value", (const uint8_t *)"one", value, 3U);
  WT_EXPECT_U64("of the right lengths", 3U, (uint64_t)value_length);

  WT_EXPECT_STATUS("an index that was never inserted is not there", WT_ERR_CLOSED,
                   wt_qpack_dynamic_entry(&table, 2U, &name, &name_length, &value, &value_length));

  /* An empty name and value with NULL pointers are legal: the entry has no bytes to
   * copy, and the guards in the insert are what keep those NULLs away from
   * memcpy's nonnull parameters. */
  WT_EXPECT_OK("an entry with no name and no value inserts",
               wt_qpack_dynamic_insert(&table, NULL, 0U, NULL, 0U, &index));
  WT_EXPECT_U64("at the next absolute index", 2U, index);
  WT_EXPECT_OK("and it reads back",
               wt_qpack_dynamic_entry(&table, 2U, &name, &name_length, &value, &value_length));
  WT_EXPECT_U64("with no name bytes", 0U, (uint64_t)name_length);
  WT_EXPECT_U64("and no value bytes", 0U, (uint64_t)value_length);
}

static void test_eviction_keeps_indices(void) {
  wt_qpack_dynamic_table_t table;
  uint64_t index = 0U;
  const uint8_t *name = NULL;
  const uint8_t *value = NULL;
  size_t name_length = 0U;
  size_t value_length = 0U;

  /* Room for exactly two 3+3 entries. */
  wt_qpack_dynamic_init(&table, 2U * entry_size(3U, 3U));
  WT_EXPECT_OK("the first inserts", wt_qpack_dynamic_insert(&table, (const uint8_t *)"a-1", 3U,
                                                            (const uint8_t *)"v-1", 3U, &index));
  WT_EXPECT_OK("the second inserts", wt_qpack_dynamic_insert(&table, (const uint8_t *)"a-2", 3U,
                                                             (const uint8_t *)"v-2", 3U, &index));
  WT_EXPECT_U64("and the table is full", 2U, (uint64_t)table.count);

  /* The third evicts the first, and the survivor keeps the index it was given. */
  WT_EXPECT_OK("the third inserts", wt_qpack_dynamic_insert(&table, (const uint8_t *)"a-3", 3U,
                                                            (const uint8_t *)"v-3", 3U, &index));
  WT_EXPECT_U64("at absolute index two", 2U, index);
  WT_EXPECT_U64("with two entries live", 2U, (uint64_t)table.count);
  WT_EXPECT_U64("one of them evicted", 1U, table.dropped);
  WT_EXPECT_STATUS("the evicted index is gone", WT_ERR_CLOSED,
                   wt_qpack_dynamic_entry(&table, 0U, &name, &name_length, &value, &value_length));
  WT_EXPECT_OK("but the second entry still answers to one",
               wt_qpack_dynamic_entry(&table, 1U, &name, &name_length, &value, &value_length));
  WT_EXPECT_BYTES("with its own bytes", (const uint8_t *)"a-2", name, 3U);
  WT_EXPECT_OK("and the third is there",
               wt_qpack_dynamic_entry(&table, 2U, &name, &name_length, &value, &value_length));
  WT_EXPECT_BYTES("with its bytes too", (const uint8_t *)"v-3", value, 3U);
}

static void test_capacity_and_limits(void) {
  wt_qpack_dynamic_table_t table;
  uint64_t index = 0U;

  /* Zero capacity is legal and means the peer may not use a dynamic table. */
  wt_qpack_dynamic_init(&table, 0U);
  WT_EXPECT_STATUS(
      "no entry fits a zero-capacity table", WT_ERR_LIMIT,
      wt_qpack_dynamic_insert(&table, (const uint8_t *)"a", 1U, (const uint8_t *)"b", 1U, &index));

  /* An entry larger than the capacity is refused rather than stored partially. */
  wt_qpack_dynamic_init(&table, entry_size(3U, 3U) - 1U);
  WT_EXPECT_STATUS("an oversized entry is refused", WT_ERR_LIMIT,
                   wt_qpack_dynamic_insert(&table, (const uint8_t *)"a-b", 3U,
                                           (const uint8_t *)"v-b", 3U, &index));
  WT_EXPECT_U64("and the table is untouched", 0U, (uint64_t)table.count);

  /* A capacity that shrinks evicts until the size fits, and can empty the table. */
  wt_qpack_dynamic_init(&table, 4096U);
  WT_EXPECT_OK("two entries insert", wt_qpack_dynamic_insert(&table, (const uint8_t *)"a-1", 3U,
                                                             (const uint8_t *)"v-1", 3U, &index));
  WT_EXPECT_OK("and the second", wt_qpack_dynamic_insert(&table, (const uint8_t *)"a-2", 3U,
                                                         (const uint8_t *)"v-2", 3U, &index));
  wt_qpack_dynamic_set_capacity(&table, entry_size(3U, 3U));
  WT_EXPECT_U64("a smaller capacity evicts the oldest", 1U, (uint64_t)table.count);
  WT_EXPECT_U64("leaving the newest", 1U, table.dropped);
  WT_EXPECT_U64("and the size within it", (uint64_t)entry_size(3U, 3U), (uint64_t)table.size);
  wt_qpack_dynamic_set_capacity(&table, 0U);
  WT_EXPECT_U64("and zero capacity empties it", 0U, (uint64_t)table.count);
  WT_EXPECT_U64("with nothing left to size", 0U, (uint64_t)table.size);

  /* The fixed entry bound is this build's, and it is reported as a limit. */
  wt_qpack_dynamic_init(&table, 4096U);
  {
    size_t i;
    for (i = 0U; i < (size_t)WT_QPACK_DYNAMIC_MAX_ENTRIES; i++) {
      WT_EXPECT_OK("an entry fits the table",
                   wt_qpack_dynamic_insert(&table, (const uint8_t *)"n", 1U, (const uint8_t *)"v",
                                           1U, &index));
    }
    WT_EXPECT_U64("which is now full", (uint64_t)WT_QPACK_DYNAMIC_MAX_ENTRIES,
                  (uint64_t)table.count);
  }
}

/* RFC 9204 section 3.2.2 warns about this exact shape, and an audit found the table doing it: an instruction
 * whose name or value is a REFERENCE INTO THE TABLE (a duplicate, or an insert naming a dynamic entry) is
 * decoded into a view, and applying it EVICTS entries -- which compacts the arena the view points into -- before
 * copying. The bytes then stored are whatever moved over them. The harness that found it duplicated entry 0 of a
 * two-entry table and got entry 1's name and value; ASan reported an overlapping `memcpy` at the copy. */
static void test_a_duplicate_of_a_live_entry_copies_that_entry(void) {
  wt_qpack_dynamic_table_t table;
  uint64_t index = 0U;
  const uint8_t *name = NULL;
  const uint8_t *value = NULL;
  size_t name_length = 0U;
  size_t value_length = 0U;

  /* A capacity that holds two of these entries and no more, so the duplicate has to evict something before it
   * copies. (Each entry is name + value + 32, so 100 holds two 18-byte entries and nothing else.) */
  wt_qpack_dynamic_init(&table, 100U);
  WT_EXPECT_OK("the first entry inserts",
               wt_qpack_dynamic_insert(&table, (const uint8_t *)"aaaaaaaa", 8U,
                                       (const uint8_t *)"1111", 4U, &index));
  WT_EXPECT_OK("and a second", wt_qpack_dynamic_insert(&table, (const uint8_t *)"bbbbbbbb", 8U,
                                                       (const uint8_t *)"2222", 4U, &index));

  /* The views are taken BEFORE the insert, exactly as the encoder-stream decoder takes them: they point into the
   * table's arena. */
  WT_EXPECT_OK("the first entry is readable",
               wt_qpack_dynamic_entry(&table, 0U, &name, &name_length, &value, &value_length) !=
                   WT_OK);
  WT_EXPECT_U64("with its name length", 8U, (uint64_t)name_length);
  WT_EXPECT_OK("and duplicating it from its own bytes",
               wt_qpack_dynamic_insert(&table, name, name_length, value, value_length, &index));

  /* The SOURCE was evicted to make room -- that is what makes this the bug's exact case -- and the duplicate
   * must still carry the FIRST entry's bytes rather than the second's, which is what a copy performed after the
   * arena was compacted over them stored. */
  WT_EXPECT_STATUS("the source entry was evicted to make room", WT_ERR_CLOSED,
                   wt_qpack_dynamic_entry(&table, 0U, &name, &name_length, &value, &value_length));
  WT_EXPECT_U64("while the duplicate lives on", 2U, (uint64_t)table.count);
  WT_EXPECT_OK("and the duplicate reads back",
               wt_qpack_dynamic_entry(&table, index, &name, &name_length, &value, &value_length));
  WT_EXPECT_U64("with the name it duplicated", 8U, (uint64_t)name_length);
  WT_EXPECT_BYTES("byte for byte", (const uint8_t *)"aaaaaaaa", name, 8U);
  WT_EXPECT_BYTES("and the value it duplicated", (const uint8_t *)"1111", value, 4U);
}

int main(void) {
  test_insert_and_lookup();
  test_a_duplicate_of_a_live_entry_copies_that_entry();
  test_eviction_keeps_indices();
  test_capacity_and_limits();
  WT_TEST_MAIN_END("wt_qpack_dynamic");
}
