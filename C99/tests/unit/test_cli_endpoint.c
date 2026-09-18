/* The tools' local socket (Phase 9).
 *
 * This is the socket half of the plan's "run local IPv4 and IPv6 packet sessions", tested for what
 * it is: the address decides the family, a listener binds and reports the port it actually got, a
 * client parses without binding, and the failures that come from the system stay the system's
 * (a refused bind is not translated into an invented status). IPv4 is asserted unconditionally
 * because every machine this builds on has it; IPv6 is asserted when the system has it and reported
 * as skipped when it does not, because a test that fails on a machine without IPv6 is a test about
 * the machine rather than about this code. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/cli/endpoint.h"

static void test_the_address_decides_the_family(void) {
  wt_cli_endpoint_t endpoint;

  /* A client parses and does not bind: two clients on one machine must be able to talk to one
   * server, which a bound local port would prevent. */
  WT_EXPECT_OK("an IPv4 address parses", wt_cli_endpoint_open(&endpoint, "127.0.0.1:4433", 0));
  WT_EXPECT_INT("as IPv4", (int)WT_UDP_IPV4, (int)endpoint.address.family);
  WT_EXPECT_STR("named", "ipv4", wt_cli_family_name(endpoint.address.family));
  WT_EXPECT_U64("with the port", 4433U, (uint64_t)endpoint.address.port);
  WT_EXPECT_U64("and nothing bound", 0U, (uint64_t)endpoint.bound_port);
  wt_cli_endpoint_close(&endpoint);

  WT_EXPECT_OK("a bracketed IPv6 address parses", wt_cli_endpoint_open(&endpoint, "[::1]:4433", 0));
  WT_EXPECT_INT("as IPv6", (int)WT_UDP_IPV6, (int)endpoint.address.family);
  WT_EXPECT_U64("with its port", 4433U, (uint64_t)endpoint.address.port);
  wt_cli_endpoint_close(&endpoint);

  /* "Every interface" is a WILDCARD ADDRESS rather than an empty host: a host with no family is a
   * guess about which family was meant, and the runtime's parser refuses to make it. */
  WT_EXPECT_OK("0.0.0.0:port parses", wt_cli_endpoint_open(&endpoint, "0.0.0.0:4433", 0));
  WT_EXPECT_INT("as IPv4", (int)WT_UDP_IPV4, (int)endpoint.address.family);
  WT_EXPECT_U64("with the port", 4433U, (uint64_t)endpoint.address.port);
  wt_cli_endpoint_close(&endpoint);
  WT_EXPECT_STATUS("and an empty host is refused rather than guessed", WT_ERR_INVALID_ARGUMENT,
                   wt_cli_endpoint_open(&endpoint, ":4433", 0));

  /* A name that is not an address is the parser's refusal, unchanged. */
  WT_EXPECT_STATUS("a bare name without a port is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_cli_endpoint_open(&endpoint, "localhost", 0));
  WT_EXPECT_STATUS("and an empty string too", WT_ERR_INVALID_ARGUMENT,
                   wt_cli_endpoint_open(&endpoint, "", 0));
  WT_EXPECT_STATUS("as is a NULL", WT_ERR_INVALID_ARGUMENT,
                   wt_cli_endpoint_open(&endpoint, NULL, 0));
}

static void test_a_listener_binds_and_says_what_it_got(void) {
  wt_cli_endpoint_t endpoint;
  FILE *stream;
  char buffer[512];
  size_t read_length;

  /* Port 0 asks the system for one, and the port ACTUALLY bound is what a script must read: that is
   * what makes a listener usable by a test at all. */
  WT_EXPECT_OK("an IPv4 listener binds on a chosen port",
               wt_cli_endpoint_open(&endpoint, "127.0.0.1:0", 1));
  WT_EXPECT_TRUE("and reports a port", endpoint.bound_port != 0U);
  WT_EXPECT_U64("which is the same one the runtime reports", (uint64_t)endpoint.bound_port,
                (uint64_t)endpoint.socket.port);

  stream = tmpfile();
  WT_EXPECT_TRUE("a stream opens", stream != NULL);
  if (stream != NULL) {
    wt_cli_endpoint_write_json(&endpoint, "127.0.0.1:0", stream);
    rewind(stream);
    read_length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
    buffer[read_length] = '\0';
    fclose(stream);
    WT_EXPECT_TRUE("the JSON names the family", strstr(buffer, "\"family\":\"ipv4\"") != NULL);
    WT_EXPECT_TRUE("and carries the bound port", strstr(buffer, "\"boundPort\":") != NULL);
    WT_EXPECT_TRUE("with the address as given",
                   strstr(buffer, "\"address\":\"127.0.0.1:0\"") != NULL);
  }
  wt_cli_endpoint_close(&endpoint);
  WT_EXPECT_INT("and closes", 0, endpoint.open);

  /* A second listener on the same port is the system's refusal, passed through rather than
   * translated: a tool that reported its own status here would hide the reason. */
  {
    wt_cli_endpoint_t first;
    wt_cli_endpoint_t second;
    char again[32];
    WT_EXPECT_OK("a first listener binds", wt_cli_endpoint_open(&first, "127.0.0.1:0", 1));
    (void)snprintf(again, sizeof(again), "127.0.0.1:%u", (unsigned)first.bound_port);
    WT_EXPECT_TRUE("the same port is refused for a second listener",
                   wt_cli_endpoint_open(&second, again, 1) != WT_OK);
    WT_EXPECT_INT("and nothing is left open", 0, second.open);
    wt_cli_endpoint_close(&first);
  }

  /* IPv6, where the machine has it. */
  {
    wt_status_t status = wt_cli_endpoint_open(&endpoint, "[::1]:0", 1);
    if (status == WT_OK) {
      WT_EXPECT_INT("an IPv6 listener is IPv6", (int)WT_UDP_IPV6, (int)endpoint.address.family);
      WT_EXPECT_TRUE("and reports a port", endpoint.bound_port != 0U);
      wt_cli_endpoint_close(&endpoint);
    } else {
      /* Recorded rather than hidden: the run says the machine has no IPv6 loopback, and the other
       * assertions still run. */
      WT_EXPECT_STATUS("this machine has no IPv6 loopback to bind", WT_ERR_UNSUPPORTED, status);
    }
  }
}

int main(void) {
  test_the_address_decides_the_family();
  test_a_listener_binds_and_says_what_it_got();
  WT_TEST_MAIN_END("wt_cli_endpoint");
}
