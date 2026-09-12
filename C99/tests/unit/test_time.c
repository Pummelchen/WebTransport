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
    WT_EXPECT_U64("with nothing remaining", 0U,
                  wt_deadline_remaining(start, 0U, start));
  }

  /* Exactly at the deadline counts as passed. Half-open, so that a caller's
   * loop terminates on the boundary rather than one tick later. */
  WT_EXPECT_INT("exactly at the deadline has passed", 1,
                wt_deadline_passed(100U, 50U, 150U));
  WT_EXPECT_INT("a tick before it has not", 0,
                wt_deadline_passed(100U, 50U, 149U));
  WT_EXPECT_U64("remaining at a tick before", 1U,
                wt_deadline_remaining(100U, 50U, 149U));

  /* The counter wrapping is the case the subtraction exists for: a deadline
   * near the top of the range must not read as long expired when the clock has
   * wrapped past it. With a subtraction, `now - start` is the true elapsed
   * interval as long as the elapsed time is less than 2^63 microseconds. */
  {
    uint64_t start = UINT64_MAX - 100U;
    uint64_t now = start + 50U; /* still before the deadline */
    WT_EXPECT_INT("a deadline near the top of the counter has not passed", 0,
                  wt_deadline_passed(start, 200U, now));
    WT_EXPECT_U64("and has the right interval left", 150U,
                  wt_deadline_remaining(start, 200U, now));
    /* And past it, with now wrapped to a small value. */
    now = start + 300U;
    WT_EXPECT_INT("and passes once the interval elapses", 1,
                  wt_deadline_passed(start, 200U, now));
    WT_EXPECT_U64("with nothing remaining", 0U,
                  wt_deadline_remaining(start, 200U, now));
  }

  WT_TEST_MAIN_END("wt_time");
}
