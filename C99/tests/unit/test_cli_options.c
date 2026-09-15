/* The command-line tools' options (Phase 9).
 *
 * The parser is tested directly, which is the reason it is a library function rather than a
 * block of argv walking inside a main: every rule here -- a missing value, a flag that must not
 * swallow the next flag, an unsupported mode refused by name, a timeout that is digits only --
 * is a behaviour a script depends on, and each one is a failing check rather than a manual
 * attempt. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/cli/options.h"

static wt_status_t parse(const char *const *argv, int argc, wt_cli_options_t *options,
                         const char **error) {
  return wt_cli_options_parse(options, argc, argv, error, NULL);
}

static void test_the_required_flags(void) {
  const char *argv[] = {"wt-conformance-c99", "--connect",       "--transport", "packet",
                        "--trust",           "system",            "--origin",    "https://localhost",
                        "--protocol",        "chat",              "--exchange",  "datagram",
                        "--message",         "hello",             "--timeout-ms", "2500",
                        "--scenario",        "all",               "--json",
                        "localhost:4433"};
  wt_cli_options_t options;
  const char *error = NULL;

  WT_EXPECT_OK("every flag the plan names parses", parse(argv, (int)(sizeof(argv) / sizeof(argv[0])),
                                                          &options, &error));
  WT_EXPECT_INT("as a connect", (int)WT_CLI_MODE_CONNECT, (int)options.mode);
  WT_EXPECT_STR("with the address", "localhost:4433", options.address);
  WT_EXPECT_INT("the packet transport", (int)WT_CLI_TRANSPORT_PACKET, (int)options.transport);
  WT_EXPECT_INT("system trust", (int)WT_CLI_TRUST_SYSTEM, (int)options.trust);
  WT_EXPECT_STR("the origin", "https://localhost", options.origin);
  WT_EXPECT_STR("the protocol", "chat", options.protocol);
  WT_EXPECT_INT("the datagram exchange", (int)WT_CLI_EXCHANGE_DATAGRAM, (int)options.exchange);
  WT_EXPECT_STR("the message", "hello", options.message);
  WT_EXPECT_U64("the timeout", 2500U, options.timeout_ms);
  WT_EXPECT_INT("the scenario", 1, options.scenario_all);
  WT_EXPECT_INT("and json output", 1, options.json);
  WT_EXPECT_TRUE("settings validation off unless asked", options.settings_validation == 0);

  /* The defaults are what a tool runs with when a flag is omitted. */
  {
    const char *minimal[] = {"wt-client-c99", "--connect", "localhost:4433"};
    wt_cli_options_t plain;
    WT_EXPECT_OK("a minimal command line parses",
                 parse(minimal, 3, &plain, &error));
    WT_EXPECT_INT("with packet transport", (int)WT_CLI_TRANSPORT_PACKET, (int)plain.transport);
    WT_EXPECT_INT("system trust", (int)WT_CLI_TRUST_SYSTEM, (int)plain.trust);
    WT_EXPECT_INT("a stream exchange", (int)WT_CLI_EXCHANGE_STREAM, (int)plain.exchange);
    WT_EXPECT_U64("and a five second timeout", 5000U, plain.timeout_ms);
    WT_EXPECT_INT("where the address is positional", 1, plain.address != NULL);
    /* The default token is the draft-16 one, which is the whole point of the selection: it must not become an
     * accidental legacy default just because zero is a convenient initialiser (F-02b). */
    WT_EXPECT_INT("and the draft-16 upgrade token", (int)WT_CLI_UPGRADE_TOKEN_DRAFT16,
                  (int)plain.upgrade_token);
    WT_EXPECT_INT("which the caller did not have to ask for", 0, plain.upgrade_token_set);
  }
}

static void test_help_and_version_are_not_flags_to_refuse(void) {
  wt_cli_options_t options;
  const char *error = NULL;
  {
    const char *argv[] = {"wt-client-c99", "--help"};
    WT_EXPECT_OK("--help parses", parse(argv, 2, &options, &error));
    WT_EXPECT_INT("and is recorded", 1, options.help);
  }
  {
    const char *argv[] = {"wt-client-c99", "-h"};
    WT_EXPECT_OK("-h parses", parse(argv, 2, &options, &error));
    WT_EXPECT_INT("as help too", 1, options.help);
  }
  {
    const char *argv[] = {"wt-client-c99", "--version"};
    WT_EXPECT_OK("--version parses", parse(argv, 2, &options, &error));
    WT_EXPECT_INT("and is recorded", 1, options.version);
  }
  {
    /* Asking what a tool does is not asking it to do anything: the mode check must not refuse it. */
    const char *argv[] = {"wt-client-c99", "--help"};
    wt_cli_options_t asked;
    WT_EXPECT_OK("and --help alone parses", parse(argv, 2, &asked, &error));
    WT_EXPECT_INT("with no mode", (int)WT_CLI_MODE_NONE, (int)asked.mode);
  }
}

static void test_unsupported_modes_are_refused_by_name(void) {
  wt_cli_options_t options;
  const char *error = NULL;

  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--transport", "quic"};
    WT_EXPECT_STATUS("an unsupported transport is refused", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 5, &options, &error));
    WT_EXPECT_STR("with a message naming what was refused", "unsupported transport", error);
  }
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--trust", "anything-goes"};
    WT_EXPECT_STATUS("an unsupported trust mode is refused", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 5, &options, &error));
    WT_EXPECT_STR("by name", "unsupported trust mode", error);
  }
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--exchange", "both"};
    WT_EXPECT_STATUS("an unsupported exchange is refused", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 5, &options, &error));
    WT_EXPECT_STR("by name", "unsupported exchange", error);
  }
  {
    const char *argv[] = {"wt-conformance-c99", "--scenario", "one"};
    WT_EXPECT_STATUS("an unsupported scenario is refused", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 3, &options, &error));
    WT_EXPECT_STR("by name", "unsupported scenario", error);
  }
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--wat"};
    WT_EXPECT_STATUS("an unknown flag is refused", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 4, &options, &error));
    WT_EXPECT_STR("by that name", "unknown flag", error);
  }
}

static void test_a_value_is_never_the_next_flag(void) {
  wt_cli_options_t options;
  const char *error = NULL;
  const char *argument = NULL;

  {
    const char *argv[] = {"wt-client-c99", "--transport", "--connect", "h:1"};
    WT_EXPECT_STATUS("a flag with no value is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_cli_options_parse(&options, 4, argv, &error, &argument));
    WT_EXPECT_STR("with a message saying so", "missing value", error);
    WT_EXPECT_STR("and the flag that needed it", "--transport", argument);
  }
  {
    /* A flag that TAKES a value at the end of the line has none, and that is a parse error
     * rather than something the check has to notice later. */
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--timeout-ms"};
    WT_EXPECT_STATUS("a value-taking flag at the end has no value", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 4, &options, &error));
    WT_EXPECT_STR("and says so", "missing value", error);
  }
  {
    /* A single dash is not a flag: a negative-looking address is still an address. */
    const char *argv[] = {"wt-client-c99", "--connect", "-host:1"};
    WT_EXPECT_OK("a single-dash argument is a value", parse(argv, 3, &options, &error));
    WT_EXPECT_STR("taken as the address", "-host:1", options.address);
  }
}

static void test_timeouts_are_digits_only(void) {
  wt_cli_options_t options;
  const char *error = NULL;

  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--timeout-ms", "0"};
    WT_EXPECT_OK("a zero timeout parses", parse(argv, 5, &options, &error));
    WT_EXPECT_U64("as zero", 0U, options.timeout_ms);
    WT_EXPECT_STATUS("and is refused by the check, because it would wait forever",
                     WT_ERR_INVALID_ARGUMENT, wt_cli_options_check(&options, &error));
    WT_EXPECT_STR("with that reason", "a zero timeout would wait forever", error);
  }
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--timeout-ms", "5s"};
    WT_EXPECT_STATUS("a timeout with a suffix is refused", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 5, &options, &error));
    WT_EXPECT_STR("as an invalid timeout", "invalid timeout", error);
  }
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--timeout-ms",
                          "99999999999999999999999"};
    WT_EXPECT_STATUS("a timeout that would overflow is refused", WT_ERR_INVALID_ARGUMENT,
                     parse(argv, 5, &options, &error));
  }
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--timeout-ms", "-5"};
    WT_EXPECT_STATUS("a negative timeout is refused as a missing value",
                     WT_ERR_INVALID_ARGUMENT, parse(argv, 5, &options, &error));
  }
}

static void test_the_check_is_one_place(void) {
  wt_cli_options_t options = wt_cli_options_default();
  const char *error = NULL;

  WT_EXPECT_STATUS("no mode is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_cli_options_check(&options, &error));
  WT_EXPECT_STR("with the reason", "no mode: pass --listen or --connect", error);

  options.mode = WT_CLI_MODE_LISTEN;
  WT_EXPECT_STATUS("no address is refused too", WT_ERR_INVALID_ARGUMENT,
                   wt_cli_options_check(&options, &error));
  WT_EXPECT_STR("with its reason", "no address: pass host:port", error);

  options.address = "localhost:4433";
  WT_EXPECT_OK("and both together pass", wt_cli_options_check(&options, &error));

  /* The development bypass outside loopback is refused here rather than at the handshake: the
   * library enforces the same rule, and a tool should not offer what the library will refuse. */
  options.trust = WT_CLI_TRUST_LOCAL_DEVELOPMENT;
  options.address = "example.com:443";
  WT_EXPECT_STATUS("the bypass for a real address is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_cli_options_check(&options, &error));
  WT_EXPECT_STR("with the loopback reason",
                "the development bypass is refused for a non-loopback address", error);
  options.address = "127.0.0.1:4433";
  WT_EXPECT_OK("and allowed for loopback", wt_cli_options_check(&options, &error));
  options.address = "localhost:4433";
  WT_EXPECT_OK("by name as well", wt_cli_options_check(&options, &error));
}

static void test_the_names_and_the_json(void) {
  wt_cli_options_t options = wt_cli_options_default();
  FILE *stream;
  char buffer[512];
  size_t read_length;

  WT_EXPECT_STR("a mode has a name", "connect", wt_cli_mode_name(WT_CLI_MODE_CONNECT));
  WT_EXPECT_STR("a transport has one", "packet", wt_cli_transport_name(WT_CLI_TRANSPORT_PACKET));
  WT_EXPECT_STR("trust has one", "system", wt_cli_trust_name(WT_CLI_TRUST_SYSTEM));
  WT_EXPECT_STR("and an exchange", "datagram", wt_cli_exchange_name(WT_CLI_EXCHANGE_DATAGRAM));

  /* The JSON is what a script reads, so it is checked as text: a field that moved would change
   * a machine's input, and that is the kind of change this test exists to refuse. */
  options.mode = WT_CLI_MODE_CONNECT;
  options.address = "localhost:4433";
  options.json = 1;
  options.timeout_ms = 1500U;
  options.trust_set = 1;
  stream = tmpfile();
  WT_EXPECT_TRUE("a temporary stream opens", stream != NULL);
  if (stream != NULL) {
    wt_cli_options_write_json(&options, stream);
    rewind(stream);
    read_length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
    buffer[read_length] = '\0';
    fclose(stream);
    WT_EXPECT_TRUE("the report names the mode", strstr(buffer, "\"mode\":\"connect\"") != NULL);
    WT_EXPECT_TRUE("the address", strstr(buffer, "\"address\":\"localhost:4433\"") != NULL);
    WT_EXPECT_TRUE("the timeout", strstr(buffer, "\"timeoutMs\":1500") != NULL);
    WT_EXPECT_TRUE("the transport", strstr(buffer, "\"transport\":\"packet\"") != NULL);
    WT_EXPECT_TRUE("a missing field as null", strstr(buffer, "\"origin\":null") != NULL);
    WT_EXPECT_TRUE("and ends the object", buffer[read_length - 2U] == '}');
  }

  /* A caller-supplied string is ESCAPED. The writer had a comment saying no escaping was needed and that "the
   * library already owns" an escaper -- it did not, and an audit put a quote, a comma and a brace into `--origin`
   * and watched a new member appear in the object a script was reading. `http://a"b\nc` is the shape: a quote, a
   * control byte and a backslash, all three of which RFC 8259 requires to be escaped. */
  memset(&options, 0, sizeof(options));
  options.mode = WT_CLI_MODE_CONNECT;
  options.address = "localhost:4433";
  options.origin = "http://a\"b\\c";
  options.protocol = "chat\tv1";
  stream = tmpfile();
  WT_EXPECT_TRUE("a second temporary stream opens", stream != NULL);
  if (stream != NULL) {
    wt_cli_options_write_json(&options, stream);
    rewind(stream);
    read_length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
    buffer[read_length] = '\0';
    fclose(stream);
    WT_EXPECT_TRUE("the quote is escaped",
                   strstr(buffer, "\"origin\":\"http://a\\\"b\\\\c\"") != NULL);
    WT_EXPECT_TRUE("the tab is escaped as \\t", strstr(buffer, "\"protocol\":\"chat\\tv1\"") != NULL);
    WT_EXPECT_TRUE("and no raw quote ends the value early",
                   strstr(buffer, "\"origin\":\"http://a\"") == NULL);
  }
}

static void test_the_upgrade_token_flag(void) {
  wt_cli_options_t options;
  const char *error = NULL;
  const char *argument = NULL;

  /* Both names select, and each selects the token it names. */
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--upgrade-token", "legacy"};
    WT_EXPECT_OK("the legacy token parses", parse(argv, 5, &options, &error));
    WT_EXPECT_INT("and is selected", (int)WT_CLI_UPGRADE_TOKEN_LEGACY, (int)options.upgrade_token);
    WT_EXPECT_INT("with the caller's choice recorded", 1, options.upgrade_token_set);
    WT_EXPECT_STR("under its own name", "legacy", wt_cli_upgrade_token_name(options.upgrade_token));
  }
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--upgrade-token", "draft16"};
    WT_EXPECT_OK("the draft-16 token parses", parse(argv, 5, &options, &error));
    WT_EXPECT_INT("and is selected", (int)WT_CLI_UPGRADE_TOKEN_DRAFT16, (int)options.upgrade_token);
    WT_EXPECT_STR("under its own name", "draft16", wt_cli_upgrade_token_name(options.upgrade_token));
  }
  /* A value that is neither is refused by name, and the argument named is the value rather than the flag. */
  {
    const char *argv[] = {"wt-client-c99", "--connect", "h:1", "--upgrade-token", "webtransport-h2"};
    WT_EXPECT_STATUS("an unknown token is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_cli_options_parse(&options, 5, argv, &error, &argument));
    WT_EXPECT_STR("with a message naming what was refused", "unsupported upgrade token", error);
    WT_EXPECT_STR("and the value that caused it", "webtransport-h2", argument);
  }
  /* A listener sends no CONNECT, so asking for a token there would be stating something about a request it does
   * not make. Refused rather than ignored -- and only when the flag was actually given, which the case below
   * checks, because the draft-16 default must stay valid for every mode. */
  {
    const char *argv[] = {"wt-server-c99", "--listen", "h:1", "--upgrade-token", "legacy"};
    WT_EXPECT_OK("a listener may parse the flag", parse(argv, 5, &options, &error));
    WT_EXPECT_STATUS("but the token is refused for a listener", WT_ERR_INVALID_ARGUMENT,
                     wt_cli_options_check(&options, &error));
    WT_EXPECT_STR("with the client-only reason",
                  "--upgrade-token is a client's option: it names the CONNECT's :protocol", error);
  }
  {
    const char *argv[] = {"wt-server-c99", "--listen", "h:1"};
    WT_EXPECT_OK("a listener without the flag parses", parse(argv, 3, &options, &error));
    WT_EXPECT_OK("and passes the check at the draft-16 default", wt_cli_options_check(&options, &error));
  }
  /* And the selection is in the report a script reads, not only on the command line. */
  {
    FILE *stream;
    char buffer[512];
    size_t read_length;
    options = wt_cli_options_default();
    options.mode = WT_CLI_MODE_CONNECT;
    options.address = "localhost:4433";
    options.upgrade_token = WT_CLI_UPGRADE_TOKEN_LEGACY;
    stream = tmpfile();
    WT_EXPECT_TRUE("a temporary stream opens", stream != NULL);
    if (stream != NULL) {
      wt_cli_options_write_json(&options, stream);
      rewind(stream);
      read_length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
      buffer[read_length] = '\0';
      fclose(stream);
      WT_EXPECT_TRUE("the report names the legacy token",
                     strstr(buffer, "\"upgradeToken\":\"legacy\"") != NULL);
    }
  }
}

int main(void) {
  test_help_and_version_are_not_flags_to_refuse();
  test_the_required_flags();
  test_unsupported_modes_are_refused_by_name();
  test_a_value_is_never_the_next_flag();
  test_timeouts_are_digits_only();
  test_the_check_is_one_place();
  test_the_names_and_the_json();
  test_the_upgrade_token_flag();
  WT_TEST_MAIN_END("wt_cli_options");
}
