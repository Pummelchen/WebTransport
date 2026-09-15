/* A test harness small enough to read in one sitting.
 *
 * The plan asks for "a small internal C99 test harness for portability", and
 * that is the whole specification: no dependency, no registration machinery, no
 * allocation, and no output on success beyond one line per file. A test file is
 * a main() that calls functions full of WT_EXPECT macros and ends with
 * WT_TEST_MAIN_END, which prints the count and returns non-zero if anything
 * failed -- or if NOTHING ran: a file that asserts nothing is a file that
 * checks nothing, and reporting it as passing is how a deleted corpus goes
 * unnoticed.
 *
 * WHY THE EXPECT MACROS TAKE A LABEL. A bare `assert(a == b)` tells you that a
 * test failed and not what it was checking, and the label is what makes a CI log
 * readable without a debugger. The other half of the reason is that the values
 * are printed: a length that is one byte off is diagnosable from the log and
 * invisible from "FAIL".
 */

#ifndef WT_TEST_H
#define WT_TEST_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "webtransport/status.h"

static int wt_test_checks = 0;
static int wt_test_failures = 0;

/* Sized integers, printed in decimal. A defined static function rather than a
 * macro so that the arguments are evaluated once. */
static inline void wt_test_expect_u64(const char *label, uint64_t want, uint64_t got) {
  wt_test_checks++;
  if (want == got) return;
  wt_test_failures++;
  printf("FAIL %s: want %llu, got %llu\n", label, (unsigned long long)want,
         (unsigned long long)got);
}

static inline void wt_test_expect_int(const char *label, long want, long got) {
  wt_test_checks++;
  if (want == got) return;
  wt_test_failures++;
  printf("FAIL %s: want %ld, got %ld\n", label, want, got);
}

static inline void wt_test_expect_str(const char *label, const char *want,
                               const char *got) {
  wt_test_checks++;
  if (want == NULL || got == NULL) {
    if (want == got) return;
    wt_test_failures++;
    printf("FAIL %s: want %s, got %s\n", label, want == NULL ? "(null)" : want,
           got == NULL ? "(null)" : got);
    return;
  }
  if (strcmp(want, got) == 0) return;
  wt_test_failures++;
  printf("FAIL %s: want \"%s\", got \"%s\"\n", label, want, got);
}

static inline void wt_test_expect_true(const char *label, int condition) {
  wt_test_checks++;
  if (condition) return;
  wt_test_failures++;
  printf("FAIL %s: expected true\n", label);
}

static inline void wt_test_expect_bytes(const char *label, const uint8_t *want,
                                 const uint8_t *got, size_t len) {
  size_t i;
  wt_test_checks++;
  if (want == NULL || got == NULL) {
    if (want == got) return;
    wt_test_failures++;
    printf("FAIL %s: a side is null\n", label);
    return;
  }
  if (memcmp(want, got, len) == 0) return;
  wt_test_failures++;
  printf("FAIL %s\n     want ", label);
  for (i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

/* Asserts that `status` is WT_OK. Separate from expect_int because a status is
 * an enum whose numeric value means nothing in a log, and typed as one so that
 * -Wsign-conversion does not force a cast at every call site. */
static inline void wt_test_expect_ok(const char *label, wt_status_t status) {
  wt_test_checks++;
  if (status == WT_OK) return;
  wt_test_failures++;
  printf("FAIL %s: expected ok, got %s\n", label, wt_status_name(status));
}

static inline void wt_test_expect_status(const char *label, wt_status_t want,
                                         wt_status_t got) {
  wt_test_checks++;
  if (want == got) return;
  wt_test_failures++;
  printf("FAIL %s: want %s, got %s\n", label, wt_status_name(want),
         wt_status_name(got));
}

#define WT_EXPECT_U64(label, want, got) wt_test_expect_u64(label, want, got)
#define WT_EXPECT_INT(label, want, got) wt_test_expect_int(label, want, got)
#define WT_EXPECT_STR(label, want, got) wt_test_expect_str(label, want, got)
#define WT_EXPECT_TRUE(label, cond) wt_test_expect_true(label, cond)
#define WT_EXPECT_BYTES(label, want, got, len) \
  wt_test_expect_bytes(label, want, got, len)
#define WT_EXPECT_OK(label, status) wt_test_expect_ok(label, status)
#define WT_EXPECT_STATUS(label, want, got) \
  wt_test_expect_status(label, want, got)

#define WT_TEST_MAIN_END(name)                                              \
  do {                                                                      \
    if (wt_test_checks == 0) {                                              \
      printf("%s: NO CHECKS RAN (0 checks)\n", name);                       \
      return 1;                                                             \
    }                                                                       \
    if (wt_test_failures != 0) {                                            \
      printf("%s: %d of %d checks FAILED\n", name, wt_test_failures,        \
             wt_test_checks);                                               \
      return 1;                                                             \
    }                                                                       \
    printf("%s: all %d checks passed\n", name, wt_test_checks);             \
    return 0;                                                               \
  } while (0)

#endif /* WT_TEST_H */
