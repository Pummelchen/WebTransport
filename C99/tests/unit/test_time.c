/* Monotonic time and deadline arithmetic.
 *
 * The clock itself cannot be tested for correctness -- that it is monotonic and
 * unaffected by the system time is a property of the platform call -- but its
 * shape can be: it must not go backwards across many reads, it must advance when
 * time passes, and the deadline helpers must not report an unexpired interval as
 * expired when the microsecond counter is near its top. That last case is the
 * reason the deadline is computed as a subtraction, so it is the case the test
 * is built around.
 */

#include "wt_test.h"

#include "webtransport/time.h"

#include "time_internal.h"

/* F-28: the Windows monotonic clock converted a tick count to microseconds by multiplying first, so it wrapped
 * once the counter passed 2^64 / 10^6 ~ 1.84e13 -- about 21 days of uptime at the usual 10 MHz
 * QueryPerformanceFrequency, and minutes to hours where that frequency reports the TSC rate. After the wrap
 * `wt_now_micros` returned a SMALLER value than before, which every QUIC deadline, idle timeout and probe
 * timeout depends on not happening. The conversion is a function so this can be driven on any platform. */
static void test_a_large_counter_converts_without_wrapping(void) {
  const uint64_t frequency = 10000000U; /* the usual QueryPerformanceFrequency, 10 MHz */
  /* The first tick count whose product with 10^6 does not fit uint64: exactly where the old form wrapped. */
  const uint64_t counter = (UINT64_MAX / 1000000U) + 1U;
  uint64_t previous = wt_time_counter_to_micros(counter, frequency);
  size_t i;

  /* The exact quotient without ever forming the overflowing product: 10^6 / 10^7 is 1/10, so it is counter/10. */
  WT_EXPECT_U64("a counter past the old wrap converts to the exact value",
                counter / (frequency / 1000000U), previous);

  /* And it keeps increasing across the region the old form wrapped in. */
  for (i = 0U; i < 64U; i++) {
    uint64_t next = wt_time_counter_to_micros(counter + i + 1U, frequency);
    WT_EXPECT_TRUE("the converted value does not go backwards", next >= previous);
    previous = next;
  }

  /* The property the wrap broke, stated directly: a later counter must convert to a later time even across the
   * threshold. */
  WT_EXPECT_TRUE(
      "a counter past the wrap is later than one before it",
      wt_time_counter_to_micros(counter, frequency) >
          wt_time_counter_to_micros(counter - (frequency / 1000000U) * 1000000U, frequency));

  /* A zero frequency is the "API failed" case, answered with zero rather than a division by zero. */
  WT_EXPECT_U64("a zero frequency converts to zero", 0U, wt_time_counter_to_micros(UINT64_MAX, 0U));
}

int main(void) {
  uint64_t first = wt_now_micros();
  uint64_t second = 0U;
  size_t i;

  /* Monotonic across many reads. A clock that stepped backwards would fail
   * here, which is the property every QUIC timer depends on. */
  for (i = 0U; i < 1000U; i++) {
    second = wt_now_micros();
    WT_EXPECT_TRUE("the clock does not go backwards", second >= first);
    first = second;
  }
  WT_EXPECT_TRUE("the clock is not stuck at zero", second != 0U);

  /* Milliseconds are microseconds divided by a thousand, within the tick that
   * elapses between the two reads. */
  {
    uint64_t micros = wt_now_micros();
    uint64_t millis = wt_now_millis();
    uint64_t derived = micros / 1000U;
    uint64_t difference = (derived > millis) ? derived - millis : millis - derived;
    WT_EXPECT_TRUE("milliseconds agree with microseconds", difference <= 1U);
  }

  /* A deadline in the future has not passed and has time remaining. */
  {
    uint64_t start = wt_now_micros();
    WT_EXPECT_INT("one second from now has not passed", 0,
                  wt_deadline_passed(start, 1000000U, wt_now_micros()));
    WT_EXPECT_TRUE("and has remaining time",
                   wt_deadline_remaining(start, 1000000U, wt_now_micros()) > 0U);
  }

  /* A zero interval is already expired, because the deadline is start + 0. */
  {
    uint64_t start = wt_now_micros();
    WT_EXPECT_INT("a zero interval has passed immediately", 1,
                  wt_deadline_passed(start, 0U, start));
    WT_EXPECT_U64("with nothing remaining", 0U, wt_deadline_remaining(start, 0U, start));
  }

  /* Exactly at the deadline counts as passed. Half-open, so that a caller's
   * loop terminates on the boundary rather than one tick later. */
  WT_EXPECT_INT("exactly at the deadline has passed", 1, wt_deadline_passed(100U, 50U, 150U));
  WT_EXPECT_INT("a tick before it has not", 0, wt_deadline_passed(100U, 50U, 149U));
  WT_EXPECT_U64("remaining at a tick before", 1U, wt_deadline_remaining(100U, 50U, 149U));

  /* The counter wrapping is the case the subtraction exists for: a deadline
   * near the top of the range must not read as long expired when the clock has
   * wrapped past it. With a subtraction, `now - start` is the true elapsed
   * interval as long as the elapsed time is less than 2^63 microseconds. */
  {
    uint64_t start = UINT64_MAX - 100U;
    uint64_t now = start + 50U; /* still before the deadline */
    WT_EXPECT_INT("a deadline near the top of the counter has not passed", 0,
                  wt_deadline_passed(start, 200U, now));
    WT_EXPECT_U64("and has the right interval left", 150U, wt_deadline_remaining(start, 200U, now));
    /* And past it, with now wrapped to a small value. */
    now = start + 300U;
    WT_EXPECT_INT("and passes once the interval elapses", 1, wt_deadline_passed(start, 200U, now));
    WT_EXPECT_U64("with nothing remaining", 0U, wt_deadline_remaining(start, 200U, now));
  }

  test_a_large_counter_converts_without_wrapping();

  WT_TEST_MAIN_END("wt_time");
}
