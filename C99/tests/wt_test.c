/* The test harness's shared counters.
 *
 * wt_test.h declares them `extern` so a test may be built from more than one translation
 * unit (test_quic_connection is), and this is the one definition every test executable
 * links. A single-file test behaves exactly as it did when the counters were `static` in
 * the header. */

#include "wt_test.h"

int wt_test_checks = 0;
int wt_test_failures = 0;
