/* Status names and the error predicate.
 *
 * The names are part of the diagnostic surface a caller prints, so they are
 * pinned here: a name that changes silently breaks a log an operator is reading
 * or a test that greps for it.
 */

#include "wt_test.h"

#include "webtransport/status.h"

int main(void) {
  WT_EXPECT_STR("ok is named", "ok", wt_status_name(WT_OK));
  WT_EXPECT_STR("invalid argument is named", "invalid-argument",
                wt_status_name(WT_ERR_INVALID_ARGUMENT));
  WT_EXPECT_STR("out of memory is named", "out-of-memory",
                wt_status_name(WT_ERR_OUT_OF_MEMORY));
  WT_EXPECT_STR("timeout is named", "timeout",
                wt_status_name(WT_ERR_TIMEOUT));
  WT_EXPECT_STR("protocol is named", "protocol",
                wt_status_name(WT_ERR_PROTOCOL));
  WT_EXPECT_STR("tls is named", "tls", wt_status_name(WT_ERR_TLS));
  WT_EXPECT_STR("closed is named", "closed", wt_status_name(WT_ERR_CLOSED));
  WT_EXPECT_STR("again is named", "again", wt_status_name(WT_ERR_AGAIN));
  WT_EXPECT_STR("truncated is named", "truncated",
                wt_status_name(WT_ERR_TRUNCATED));
  WT_EXPECT_STR("limit is named", "limit", wt_status_name(WT_ERR_LIMIT));
  WT_EXPECT_STR("overflow is named", "overflow",
                wt_status_name(WT_ERR_OVERFLOW));
  WT_EXPECT_STR("state is named", "state", wt_status_name(WT_ERR_STATE));
  WT_EXPECT_STR("trust is named", "trust", wt_status_name(WT_ERR_TRUST));
  WT_EXPECT_STR("unsupported is named", "unsupported",
                wt_status_name(WT_ERR_UNSUPPORTED));

  /* A value that is not a status must not crash and must not claim to be one.
   * It reaches here from a caller that cast an integer from the wire. */
  WT_EXPECT_STR("an unknown value is named", "unknown",
                wt_status_name((wt_status_t)9999));
  WT_EXPECT_STR("a negative value is named", "unknown",
                wt_status_name((wt_status_t)-1));

  /* WT_OK is zero and is not an error; everything else is. WT_ERR_AGAIN is
   * included deliberately: the operation did not happen, so a caller that tests
   * only for "not WT_OK" is right and one that treats it as success is not. */
  WT_EXPECT_TRUE("WT_OK is zero", WT_OK == 0);
  WT_EXPECT_INT("WT_OK is not an error", 0, wt_status_is_error(WT_OK));
  WT_EXPECT_INT("again is an error", 1, wt_status_is_error(WT_ERR_AGAIN));
  WT_EXPECT_INT("closed is an error", 1, wt_status_is_error(WT_ERR_CLOSED));
  WT_EXPECT_INT("limit is an error", 1, wt_status_is_error(WT_ERR_LIMIT));

  WT_TEST_MAIN_END("wt_status");
}
