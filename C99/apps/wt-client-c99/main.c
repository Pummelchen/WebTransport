/* wt-client-c99 -- see ../../IMPLEMENTATION_PLAN.md, Phase 9.
 *
 * Phase 0 builds the executable and its link against the library, which is what
 * the plan's completion criterion asks for: "empty library and CLI stubs build
 * on every target compiler". The protocol phases fill this in, and until they do
 * the tool prints its usage and exits 3 -- a distinct status for "not
 * implemented" so that a script driving it cannot read a stub as success.
 */

#include <stdio.h>
#include <string.h>

#include "webtransport/cli/options.h"
#include "webtransport/version.h"

static int wt_usage(const char *program) {
  printf("usage: %s [options]\n", program);
  printf("\n");
  printf("WebTransport over HTTP/3, C99 implementation %s (%s).\n",
         wt_version_string(), wt_protocol_draft());
  printf("\n");
  printf("This build carries the protocol layers and the public API, but the\n");
  printf("tool does not yet drive a session over a socket: that wiring is the\n");
  printf("rest of Phase 9. It exits 3 rather than 0 so a script cannot read\n");
  printf("this as a successful run.\n");
  return 3;
}

int main(int argc, char **argv) {
  wt_cli_options_t options;
  const char *error = NULL;
  const char *argument = NULL;
  wt_status_t parsed;

  parsed = wt_cli_options_parse(&options, argc, (const char *const *)argv, &error, &argument);
  if (parsed != WT_OK) {
    fprintf(stderr, "wt: %s: %s\n", error != NULL ? error : "invalid arguments",
            argument != NULL ? argument : "");
    return 2;
  }
  /* The mode is what this tool IS unless the command line chose the other one: a client that
   * can listen and a server that can connect are one tool with two modes, which is how the
   * Swift tools are driven too. */
  if (options.mode == WT_CLI_MODE_NONE && strcmp("connect", "none") != 0) {
    options.mode = WT_CLI_MODE_CONNECT;
  }
  if (wt_cli_options_check(&options, &error) != WT_OK) {
    if (options.json != 0) {
      printf("{\"error\":\"missing mode or address\"}\n");
    } else {
      fprintf(stderr, "wt: %s\n", error != NULL ? error : "invalid arguments");
    }
    return 2;
  }
  if (options.json != 0) wt_cli_options_write_json(&options, stdout);

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
