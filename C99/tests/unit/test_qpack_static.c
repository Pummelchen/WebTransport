/* QPACK's static table (RFC 9204 section 3.1 and appendix A).
 *
 * The table itself is generated from the RFC and checked by `check-vectors.sh`,
 * so these tests are about the lookups over it and about the entries a mistake
 * would be most visible in: the first entry's empty value, a name that appears
 * twice with different values (x-frame-options), and the pseudo-headers, whose
 * repeated names are what `wt_qpack_static_find_name` has to answer for. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

static void test_entries(void) {
  wt_qpack_static_entry_t entry;

  WT_EXPECT_OK("the first entry reads", wt_qpack_static_entry(0U, &entry));
  WT_EXPECT_U64("its name length", 10U, (uint64_t)entry.name_length);
  WT_EXPECT_BYTES("its name", (const uint8_t *)":authority", (const uint8_t *)entry.name, 10U);
  WT_EXPECT_U64("and an empty value", 0U, (uint64_t)entry.value_length);

  WT_EXPECT_OK("the second entry reads", wt_qpack_static_entry(1U, &entry));
  WT_EXPECT_BYTES("as :path", (const uint8_t *)":path", (const uint8_t *)entry.name, 5U);
  WT_EXPECT_U64("with a value length of one", 1U, (uint64_t)entry.value_length);
  WT_EXPECT_BYTES("and / for one", (const uint8_t *)"/", (const uint8_t *)entry.value, 1U);

  /* The last entry, which is where an off-by-one in the extraction would show. */
  WT_EXPECT_OK("the last entry reads", wt_qpack_static_entry(98U, &entry));
  WT_EXPECT_BYTES("as x-frame-options", (const uint8_t *)"x-frame-options", (const uint8_t *)entry.name, 15U);
  WT_EXPECT_BYTES("with sameorigin", (const uint8_t *)"sameorigin", (const uint8_t *)entry.value, 10U);

  WT_EXPECT_STATUS("and one past the end is refused", WT_ERR_LIMIT,
                   wt_qpack_static_entry(99U, &entry));
  WT_EXPECT_STATUS("as is a null output", WT_ERR_INVALID_ARGUMENT,
                   wt_qpack_static_entry(0U, NULL));
}

static void test_exact_lookups(void) {
  uint64_t index = 0U;

  WT_EXPECT_OK("a pair the table carries is found",
               wt_qpack_static_find(":path", 5U, "/", 1U, &index));
  WT_EXPECT_U64("at its own index", 1U, index);

  WT_EXPECT_OK("and a later one", wt_qpack_static_find("x-frame-options", 15U, "deny", 4U, &index));
  WT_EXPECT_U64("at index 97", 97U, index);

  /* The same name with a value the table does not carry: not found, and that is
   * an answer rather than a failure -- the encoder writes a literal. */
  WT_EXPECT_STATUS("a value the table does not carry is not found", WT_ERR_CLOSED,
                   wt_qpack_static_find("x-frame-options", 15U, "nginx", 5U, &index));
  WT_EXPECT_STATUS("and neither is an unknown name", WT_ERR_CLOSED,
                   wt_qpack_static_find("x-nonexistent", 13U, "", 0U, &index));
  WT_EXPECT_STATUS("nor a name that matches only in length", WT_ERR_CLOSED,
                   wt_qpack_static_find("x-frame-optionz", 15U, "deny", 4U, &index));
}

static void test_name_lookups(void) {
  uint64_t index = 0U;

  /* :method appears seven times (CONNECT, DELETE, GET, HEAD, OPTIONS, POST, PUT,
   * at indices 15 to 21 in the RFC's own order, which is by frequency and not by
   * name -- the same order HPACK's table does NOT use, which is why the test that
   * assumed HPACK's numbering failed here). The first is what a name reference
   * uses. */
  WT_EXPECT_OK(":method is in the table", wt_qpack_static_find_name(":method", 7U, &index));
  WT_EXPECT_U64("its first entry is what is found", 15U, index);
  {
    wt_qpack_static_entry_t entry;
    WT_EXPECT_OK("and it is CONNECT", wt_qpack_static_entry(index, &entry));
    WT_EXPECT_BYTES("as the value", (const uint8_t *)"CONNECT", (const uint8_t *)entry.value, 7U);
  }

  WT_EXPECT_OK("x-frame-options appears twice",
               wt_qpack_static_find_name("x-frame-options", 15U, &index));
  WT_EXPECT_U64("and the first is found", 97U, index);

  WT_EXPECT_STATUS("a name that is not there is not found", WT_ERR_CLOSED,
                   wt_qpack_static_find_name("x-nonexistent", 13U, &index));

  /* An empty name is a legal C string of length zero, and the table has none:
   * the lookup must not match the first entry by accident. */
  WT_EXPECT_STATUS("an empty name matches nothing", WT_ERR_CLOSED,
                   wt_qpack_static_find_name("", 0U, &index));
}

int main(void) {
  test_entries();
  test_exact_lookups();
  test_name_lookups();
  WT_TEST_MAIN_END("wt_qpack_static");
}
