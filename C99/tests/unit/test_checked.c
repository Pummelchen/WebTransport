/* Checked arithmetic.
 *
 * The cases that matter are the ones where the unchecked expression is a
 * plausible-looking number: SIZE_MAX + 1 wraps to 0, and a multiplication that
 * wraps is the classic pre-allocation overflow. Each of those is asserted to be
 * refused rather than to produce a value, and the largest values that do fit are
 * asserted to be accepted so that a helper which refused everything would fail.
 */

#include "wt_test.h"

#include "webtransport/checked.h"

#include <limits.h>

int main(void) {
  size_t size_result = 0U;
  uint64_t u64_result = 0U;
  uint32_t u32_result = 0U;

  /* Addition. */
  WT_EXPECT_STATUS("1 + 2", WT_OK, wt_checked_add_size(1U, 2U, &size_result));
  WT_EXPECT_U64("1 + 2 = 3", 3U, size_result);
  WT_EXPECT_STATUS("a + 0 is exact", WT_OK, wt_checked_add_size(SIZE_MAX, 0U, &size_result));
  WT_EXPECT_U64("a + 0 = a", SIZE_MAX, size_result);
  WT_EXPECT_STATUS("the largest sum that fits", WT_OK, wt_checked_add_size(SIZE_MAX - 1U, 1U, &size_result));
  WT_EXPECT_U64("the largest sum that fits is SIZE_MAX", SIZE_MAX, size_result);
  WT_EXPECT_STATUS("SIZE_MAX + 1 is refused", WT_ERR_OVERFLOW, wt_checked_add_size(SIZE_MAX, 1U, &size_result));
  WT_EXPECT_STATUS("SIZE_MAX + SIZE_MAX is refused", WT_ERR_OVERFLOW, wt_checked_add_size(SIZE_MAX, SIZE_MAX, &size_result));
  WT_EXPECT_STATUS("addition refuses a NULL output", WT_ERR_INVALID_ARGUMENT, wt_checked_add_size(1U, 1U, NULL));

  WT_EXPECT_STATUS("u64 addition", WT_OK, wt_checked_add_u64(UINT64_MAX - 1U, 1U, &u64_result));
  WT_EXPECT_U64("u64 addition wraps nowhere", UINT64_MAX, u64_result);
  WT_EXPECT_STATUS("u64 addition refuses the wrap", WT_ERR_OVERFLOW, wt_checked_add_u64(UINT64_MAX, 1U, &u64_result));

  /* Subtraction: below zero is an overflow here, because every use of it in
   * this library is a length or an offset that must not go negative. */
  WT_EXPECT_STATUS("5 - 3", WT_OK, wt_checked_sub_size(5U, 3U, &size_result));
  WT_EXPECT_U64("5 - 3 = 2", 2U, size_result);
  WT_EXPECT_STATUS("3 - 3 is zero", WT_OK, wt_checked_sub_size(3U, 3U, &size_result));
  WT_EXPECT_U64("3 - 3 = 0", 0U, size_result);
  WT_EXPECT_STATUS("3 - 5 is refused", WT_ERR_OVERFLOW, wt_checked_sub_size(3U, 5U, &size_result));
  WT_EXPECT_STATUS("0 - 1 is refused", WT_ERR_OVERFLOW, wt_checked_sub_size(0U, 1U, &size_result));
  WT_EXPECT_STATUS("u64 subtraction refuses the wrap", WT_ERR_OVERFLOW, wt_checked_sub_u64(0U, 1U, &u64_result));

  /* Multiplication: the one a peer's length fields reach. */
  WT_EXPECT_STATUS("6 * 7", WT_OK, wt_checked_mul_size(6U, 7U, &size_result));
  WT_EXPECT_U64("6 * 7 = 42", 42U, size_result);
  WT_EXPECT_STATUS("anything times zero is zero", WT_OK, wt_checked_mul_size(SIZE_MAX, 0U, &size_result));
  WT_EXPECT_U64("times zero = 0", 0U, size_result);
  WT_EXPECT_STATUS("zero times anything is zero", WT_OK, wt_checked_mul_size(0U, SIZE_MAX, &size_result));
  WT_EXPECT_STATUS("SIZE_MAX * 1 is exact", WT_OK, wt_checked_mul_size(SIZE_MAX, 1U, &size_result));
  WT_EXPECT_U64("SIZE_MAX * 1 = SIZE_MAX", SIZE_MAX, size_result);
  WT_EXPECT_STATUS("SIZE_MAX * 2 is refused", WT_ERR_OVERFLOW, wt_checked_mul_size(SIZE_MAX, 2U, &size_result));
  WT_EXPECT_STATUS("2 * SIZE_MAX is refused", WT_ERR_OVERFLOW, wt_checked_mul_size(2U, SIZE_MAX, &size_result));
  /* The pre-allocation overflow: a count that wraps to a small number. */
  WT_EXPECT_STATUS("a count that would wrap is refused", WT_ERR_OVERFLOW, wt_checked_mul_size((SIZE_MAX / 2U) + 1U, 2U, &size_result));
  WT_EXPECT_STATUS("multiplication refuses a NULL output",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_checked_mul_size(2U, 2U, NULL));
  WT_EXPECT_STATUS("u64 multiplication refuses the wrap", WT_ERR_OVERFLOW, wt_checked_mul_u64(UINT64_MAX, 2U, &u64_result));

  /* Narrowing, refused rather than truncated. */
  WT_EXPECT_STATUS("a u64 that fits in u32", WT_OK, wt_checked_narrow_u64_to_u32(7U, &u32_result));
  WT_EXPECT_U64("narrowed value", 7U, u32_result);
  WT_EXPECT_STATUS("UINT32_MAX fits", WT_OK, wt_checked_narrow_u64_to_u32(UINT32_MAX, &u32_result));
  WT_EXPECT_U64("UINT32_MAX is unchanged", UINT32_MAX, u32_result);
  WT_EXPECT_STATUS("UINT32_MAX + 1 does not fit", WT_ERR_OVERFLOW, wt_checked_narrow_u64_to_u32((uint64_t)UINT32_MAX + 1U,
                                                &u32_result));
  WT_EXPECT_STATUS("narrowing refuses a NULL output", WT_ERR_INVALID_ARGUMENT, wt_checked_narrow_u64_to_u32(1U, NULL));
  WT_EXPECT_STATUS("a u64 that fits in size_t", WT_OK, wt_checked_narrow_u64_to_size(1U, &size_result));
  WT_EXPECT_U64("narrowed to size_t", 1U, size_result);
  WT_EXPECT_STATUS("size_t to u32", WT_OK, wt_checked_narrow_size_to_u32(1U, &u32_result));
  WT_EXPECT_STATUS("size_t to u32 refuses a NULL output",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_checked_narrow_size_to_u32(1U, NULL));

  WT_TEST_MAIN_END("wt_checked");
}
