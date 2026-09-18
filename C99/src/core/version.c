/* Library identity. See webtransport/version.h. */

#include "webtransport/version.h"

const char *wt_version_string(void) {
  /* A preprocessor stringification rather than a hand-written literal, so the
   * string and the macros cannot disagree -- which is the one thing a version
   * string has to get right. */
#define WT_STRINGIFY_INNER(x) #x
#define WT_STRINGIFY(x) WT_STRINGIFY_INNER(x)
#if WT_VERSION_PATCH == 0
  /* Releases are MAJOR.MINOR, and the patch is 0 for them. Printing it would make
   * 1.6 report itself as "1.6.0" -- a string that matches no tag and no artifact
   * name. The macros keep the third component so this stays a mirror. */
  return WT_STRINGIFY(WT_VERSION_MAJOR) "." WT_STRINGIFY(WT_VERSION_MINOR);
#else
  return WT_STRINGIFY(WT_VERSION_MAJOR) "." WT_STRINGIFY(WT_VERSION_MINOR) "." WT_STRINGIFY(
      WT_VERSION_PATCH);
#endif
#undef WT_STRINGIFY
#undef WT_STRINGIFY_INNER
}

int wt_abi_version(void) {
  return WT_ABI_VERSION;
}

const char *wt_protocol_draft(void) {
  return "draft-ietf-webtrans-http3-16";
}
