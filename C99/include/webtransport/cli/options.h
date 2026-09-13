/* The command-line tools' options (Phase 9).
 *
 * The three tools share one parser, and the reason is the plan's own requirement: the flags
 * are named in the plan (--listen, --connect, --transport packet, --trust system, --origin,
 * --protocol, --settings-validation, --exchange stream|datagram, --message, --timeout-ms,
 * --scenario all, --json) and a flag that means one thing in one tool and another in the next
 * is worse than a flag that is missing. The parser is a library function rather than a block
 * of `argv` walking inside each `main` so that this can be tested directly -- which is how a
 * tool's behaviour becomes a test rather than a manual check.
 *
 * Two rules shape it. UNSUPPORTED IS NOT UNKNOWN: `--transport packet` is the only transport
 * this build has, and `--transport quic` is refused with the reason it is refused, because a
 * tool that silently ignores a mode it cannot honour is a tool whose output means nothing. And
 * a value is never taken from the argument AFTER a flag that has none: `--json --connect host`
 * must not eat `--connect`, or a test script's typo becomes a connection attempt.
 */

#ifndef WEBTRANSPORT_CLI_OPTIONS_H
#define WEBTRANSPORT_CLI_OPTIONS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_cli_mode {
  WT_CLI_MODE_NONE = 0,
  WT_CLI_MODE_LISTEN = 1,
  WT_CLI_MODE_CONNECT = 2
} wt_cli_mode_t;

typedef enum wt_cli_transport {
  WT_CLI_TRANSPORT_PACKET = 1
} wt_cli_transport_t;

typedef enum wt_cli_trust {
  WT_CLI_TRUST_SYSTEM = 1,
  WT_CLI_TRUST_LOCAL_DEVELOPMENT = 2
} wt_cli_trust_t;

typedef enum wt_cli_exchange {
  WT_CLI_EXCHANGE_STREAM = 1,
  WT_CLI_EXCHANGE_DATAGRAM = 2
} wt_cli_exchange_t;

typedef struct wt_cli_options {
  wt_cli_mode_t mode;
  /* Where: "host:port" for either mode, as it was given. Views into argv, so they live as long
   * as the caller's argument vector. */
  const char *address;
  wt_cli_transport_t transport;
  wt_cli_trust_t trust;
  int trust_set;
  const char *origin;
  const char *protocol;
  int settings_validation;
  /* SERVER only: answer a client's first Initial with a Retry before serving it (WT-168). A client asking for it
   * is refused by `wt_cli_options_check`, because a client cannot make its server validate it. */
  int retry;
  wt_cli_exchange_t exchange;
  const char *message;
  uint64_t timeout_ms;
  int timeout_set;
  int scenario_all;
  int json;
  /* `--help` and `--version` are answered BEFORE the mode and address are checked, because a caller asking what
   * a tool does has not asked it to do anything: a parser that refused them as unknown flags made the tools
   * unusable in the one way every command-line tool must be usable. */
  int help;
  int version;
  /* How many arguments were consumed, so a caller can tell a clean parse from one that stopped
   * at an unknown flag. */
  int parsed;
} wt_cli_options_t;

/* Defaults: no mode, no address, packet transport, system trust, stream exchange, a five
 * second timeout, nothing else set. */
wt_cli_options_t wt_cli_options_default(void);

/* Parse. Returns WT_OK, or WT_ERR_INVALID_ARGUMENT with `*out_error` pointing at a static
 * message (never allocated, never a peer's text) and `*out_error_argument` at the argument
 * that caused it. The messages are stable: a test or a script may match them. */
wt_status_t wt_cli_options_parse(wt_cli_options_t *options, int argc, const char *const *argv,
                                 const char **out_error, const char **out_error_argument);

/* Whether the parsed options are usable for this tool's mode, and why not. A tool calls this
 * after parsing so that "you asked for a connect with no address" is one message from one
 * place rather than a different one in each tool. */
wt_status_t wt_cli_options_check(const wt_cli_options_t *options, const char **out_error);

/* A stable name for each enum, for the machine-readable output. */
const char *wt_cli_mode_name(wt_cli_mode_t mode);
const char *wt_cli_transport_name(wt_cli_transport_t transport);
const char *wt_cli_trust_name(wt_cli_trust_t trust);
const char *wt_cli_exchange_name(wt_cli_exchange_t exchange);

/* Print the parsed options as one JSON object, so a script reads them rather than parsing
 * prose. Written straight to `stream`; the caller owns the file. */
void wt_cli_options_write_json(const wt_cli_options_t *options, FILE *stream);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_CLI_OPTIONS_H */
