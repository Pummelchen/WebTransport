/* QPACK's encoder bookkeeping (RFC 9204 section 2.1.1).
 *
 * The rule is that an entry an unacknowledged section might reference may not be
 * evicted, so the tests are about the LIMIT that produces: nothing outstanding means
 * everything is evictable, one section at count N holds back everything below N, and
 * the smallest of several outstanding counts is the one that binds. A test that only
 * began and acknowledged one section would pass against an implementation that took the
 * largest, or the last, or the first -- which is the whole failure mode this state
 * exists to prevent. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static uint64_t add_entries(wt_qpack_dynamic_table_t *table, size_t count) {
  uint64_t index = 0U;
  size_t i;
  for (i = 0U; i < count; i++) {
    WT_EXPECT_OK("an entry inserts", wt_qpack_dynamic_insert(table, (const uint8_t *)"n", 1U,
                                                             (const uint8_t *)"v", 1U, &index));
  }
  return index + 1U;
}

static void test_nothing_outstanding(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_encoder_state_t state;
  wt_qpack_header_prefix_t prefix;
  uint64_t inserts;

  wt_qpack_dynamic_init(&table, 4096U);
  wt_qpack_encoder_state_init(&state, &table);
  inserts = add_entries(&table, 3U);

  WT_EXPECT_U64("with nothing sent, everything is evictable", inserts,
                wt_qpack_encoder_state_evictable_below(&state));

  /* A section that references nothing holds nothing back, and its prefix is zero. */
  WT_EXPECT_OK("a section with no dynamic references begins",
               wt_qpack_encoder_state_begin_section(&state, 0U, 0, &prefix));
  WT_EXPECT_U64("with a zero required count", 0U, prefix.required_insert_count);
  WT_EXPECT_U64("and a zero base", 0U, prefix.base);
  WT_EXPECT_U64("counting no outstanding section", 0U, (uint64_t)state.outstanding_count);
  WT_EXPECT_U64("so nothing is held back", inserts, wt_qpack_encoder_state_evictable_below(&state));
}

static void test_outstanding_sections_bound_eviction(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_encoder_state_t state;
  wt_qpack_header_prefix_t prefix;

  wt_qpack_dynamic_init(&table, 4096U);
  wt_qpack_encoder_state_init(&state, &table);
  (void)add_entries(&table, 2U);

  /* A section at insert count 2: the prefix names the newest entry as dynamic index
   * zero, and everything below two is held back. */
  WT_EXPECT_OK("a dynamic section begins",
               wt_qpack_encoder_state_begin_section(&state, 4U, 1, &prefix));
  WT_EXPECT_U64("with the table's insert count", 2U, prefix.required_insert_count);
  WT_EXPECT_U64("as its base too", 2U, prefix.base);
  WT_EXPECT_U64("and the limit is that count", 2U, wt_qpack_encoder_state_evictable_below(&state));

  /* More insertions do not free what the section may reference. */
  (void)add_entries(&table, 2U);
  WT_EXPECT_U64("which more insertions do not raise", 2U,
                wt_qpack_encoder_state_evictable_below(&state));
  WT_EXPECT_U64("and the newest entry is index zero from the base", 2U, prefix.base);

  /* A second section at the higher count: the SMALLEST binds. */
  WT_EXPECT_OK("a second section begins",
               wt_qpack_encoder_state_begin_section(&state, 8U, 1, &prefix));
  WT_EXPECT_U64("with the new count", 4U, prefix.required_insert_count);
  WT_EXPECT_U64("while the limit stays the older one", 2U,
                wt_qpack_encoder_state_evictable_below(&state));

  /* Acknowledging the older section raises the limit to the newer one's count. */
  WT_EXPECT_OK("the older section is acknowledged",
               wt_qpack_encoder_state_section_acknowledged(&state, 4U));
  WT_EXPECT_U64("raising the limit", 4U, wt_qpack_encoder_state_evictable_below(&state));
  WT_EXPECT_U64("with one section still outstanding", 1U, (uint64_t)state.outstanding_count);

  /* Cancelling the other frees everything. */
  WT_EXPECT_OK("the other stream is cancelled",
               wt_qpack_encoder_state_stream_cancelled(&state, 8U));
  WT_EXPECT_U64("so nothing is held back", 4U, wt_qpack_encoder_state_evictable_below(&state));
  WT_EXPECT_U64("with none outstanding", 0U, (uint64_t)state.outstanding_count);
}

static void test_records_and_limits(void) {
  wt_qpack_dynamic_table_t table;
  wt_qpack_encoder_state_t state;
  wt_qpack_header_prefix_t prefix;
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;
  size_t i;

  wt_qpack_dynamic_init(&table, 4096U);
  wt_qpack_encoder_state_init(&state, &table);
  (void)add_entries(&table, 8U);

  /* An acknowledgement for a stream with nothing outstanding is this endpoint
   * disagreeing with its own records. */
  WT_EXPECT_STATUS("an unknown acknowledgement is refused", WT_ERR_CLOSED,
                   wt_qpack_encoder_state_section_acknowledged(&state, 99U));
  /* A cancellation for one is ordinary: a peer may cancel anything. */
  WT_EXPECT_OK("an unknown cancellation is accepted",
               wt_qpack_encoder_state_stream_cancelled(&state, 99U));

  /* The same stream twice replaces its record rather than holding two: a stream
   * carries one field section at a time. */
  WT_EXPECT_OK("a section begins", wt_qpack_encoder_state_begin_section(&state, 12U, 1, &prefix));
  WT_EXPECT_OK("and begins again", wt_qpack_encoder_state_begin_section(&state, 12U, 1, &prefix));
  WT_EXPECT_U64("leaving one record", 1U, (uint64_t)state.outstanding_count);

  /* The table bound is this endpoint's, and it is reported. */
  wt_qpack_encoder_state_init(&state, &table);
  for (i = 0U; i < (size_t)WT_QPACK_MAX_OUTSTANDING_SECTIONS; i++) {
    WT_EXPECT_OK("a section fits",
                 wt_qpack_encoder_state_begin_section(&state, (uint64_t)i, 1, &prefix));
  }
  WT_EXPECT_STATUS("and one more does not", WT_ERR_LIMIT,
                   wt_qpack_encoder_state_begin_section(&state, 999U, 1, &prefix));

  /* The decoder's increments: zero says nothing, and more than was inserted cannot
   * describe a decoder that processed them. */
  wt_qpack_encoder_state_init(&state, &table);
  WT_EXPECT_STATUS("a zero increment is refused", WT_ERR_PROTOCOL,
                   wt_qpack_encoder_state_on_insert_count_increment(&state, 0U, &error));
  WT_EXPECT_U64("as a decoder stream error", WT_QPACK_ERROR_DECODER_STREAM, (uint64_t)error);
  WT_EXPECT_OK("a real increment is accepted",
               wt_qpack_encoder_state_on_insert_count_increment(&state, 3U, &error));
  WT_EXPECT_U64("and remembered", 3U, state.known_received_count);
  WT_EXPECT_STATUS("while one past the insertions is refused", WT_ERR_PROTOCOL,
                   wt_qpack_encoder_state_on_insert_count_increment(&state, 6U, &error));
}

int main(void) {
  test_nothing_outstanding();
  test_outstanding_sections_bound_eviction();
  test_records_and_limits();
  WT_TEST_MAIN_END("wt_qpack_encoder_state");
}
