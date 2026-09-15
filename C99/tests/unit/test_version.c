/* Library identity.
 *
 * The version string is assembled from the macros by the preprocessor, so the
 * only thing to check is that the two agree and that the ABI integer is the one
 * the header promises. A caller that checks the ABI version is checking the
 * thing that can break it, so it must be a positive value and stable.
 */

#include "wt_test.h"

#include "webtransport/version.h"

#include <stdlib.h>

int main(void) {
  const char *version = wt_version_string();
  const char *draft = wt_protocol_draft();

  WT_EXPECT_TRUE("the version string is not NULL", version != NULL);
  WT_EXPECT_STR("the version string is the macros'", WT_TEST_VERSION_STRING, version);
  WT_EXPECT_INT("the ABI version is the header's", WT_ABI_VERSION,
                wt_abi_version());
  WT_EXPECT_TRUE("the ABI version is positive", WT_ABI_VERSION > 0);
  WT_EXPECT_TRUE("the draft string is not NULL", draft != NULL);
  WT_EXPECT_STR("the draft is the one the plan targets",
                "draft-ietf-webtrans-http3-16", draft);

  /* The version string is static storage, so it is the same pointer on every
   * call and must not be freed by the caller. */
  WT_EXPECT_TRUE("the version string is static",
                 wt_version_string() == version);
  WT_EXPECT_TRUE("the draft string is static", wt_protocol_draft() == draft);

  WT_TEST_MAIN_END("wt_version");
}
