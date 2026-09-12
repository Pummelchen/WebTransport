/* wt-conformance-c99 -- see ../../IMPLEMENTATION_PLAN.md, Phase 9.
 *
 * Phase 0 builds the executable and its link against the library, which is what
 * the plan's completion criterion asks for: "empty library and CLI stubs build
 * on every target compiler". The protocol phases fill this in, and until they do
 * the tool prints its usage and exits 3 -- a distinct status for "not
 * implemented" so that a script driving it cannot read a stub as success.
 */

#include <stdio.h>
#include <string.h>

#include "webtransport/version.h"

static int wt_usage(const char *program) {
  printf("usage: %s [options]\n", program);
  printf("\n");
  printf("WebTransport over HTTP/3, C99 implementation %s (%s).\n",
         wt_version_string(), wt_protocol_draft());
  printf("\n");
  printf("This build has the library core only: the QUIC, TLS, HTTP/3 and\n");
  printf("WebTransport phases are not implemented yet, so the tool has nothing\n");
  printf("to run. It exits 3 rather than 0 so a script cannot read this as a\n");
  printf("successful run.\n");
  return 3;
}

int main(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      (void)wt_usage(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      printf("%s %s\n", argv[0], wt_version_string());
      return 0;
    }
  }
  return wt_usage(argv[0]);
}
