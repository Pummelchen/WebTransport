/* wt-server-c99 -- see ../../IMPLEMENTATION_PLAN.md, Phase 9.
 *
 * Phase 0 builds the executable and its link against the library, which is what
 * the plan's completion criterion asks for: "empty library and CLI stubs build
 * on every target compiler". The protocol phases fill this in, and until they do
 * the tool prints its usage and exits 3 -- a distinct status for "not
 * implemented" so that a script driving it cannot read a stub as success.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webtransport/cli/endpoint.h"
#include "session_loop.h"

#include "webtransport/cli/options.h"
#include "webtransport/version.h"

static int wt_usage(const char *program) {
  printf("usage: %s [options]\n", program);
  printf("\n");
  printf("WebTransport over HTTP/3, C99 implementation %s (%s).\n",
         wt_version_string(), wt_protocol_draft());
  printf("\n");
  printf("It listens for one peer and serves the WebTransport session that peer\n");
  printf("asks for, over the transport named by --transport, presenting the\n");
  printf("identity --trust describes. It exits non-zero when no session\n");
  printf("completes.\n");
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
  if (options.mode == WT_CLI_MODE_NONE && strcmp("listen", "none") != 0) {
    options.mode = WT_CLI_MODE_LISTEN;
  }
  if (options.help != 0) {
    /* A caller asking what the tool does gets a SUCCESS: `wt_usage` returns the "not implemented" status for the
     * stub path, and a help request is not that. */
    (void)wt_usage(argv[0]);
    return 0;
  }
  if (options.version != 0) {
    printf("%s %s\n", argv[0], wt_version_string());
    return 0;
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

  /* The socket half of the plan's "run local IPv4 and IPv6 packet sessions": the address decides
   * the family, a listener binds, and the port actually bound is reported because a listener asked
   * for port 0 has one the caller cannot know otherwise. */
  {
    wt_cli_endpoint_t endpoint;
    wt_status_t opened = wt_cli_endpoint_open(&endpoint, options.address,
                                              options.mode == WT_CLI_MODE_LISTEN ? 1 : 0);
    if (opened != WT_OK) {
      if (options.json != 0) {
        printf("{\"error\":\"endpoint\"}\n");
      } else {
        fprintf(stderr, "wt: cannot open %s\n", options.address);
      }
      return 2;
    }
    if (options.json != 0) {
      wt_cli_endpoint_write_json(&endpoint, options.address, stdout);
    } else {
      printf("endpoint: %s %s, port %u\n", wt_cli_family_name(endpoint.address.family),
             options.address, (unsigned)endpoint.bound_port);
    }
    wt_cli_endpoint_close(&endpoint);
  }

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
  /* The session itself: listen, accept one, answer it, and exchange a message. */
  if (options.mode == WT_CLI_MODE_LISTEN) {
    wt_loop_config_t loop;
    wt_loop_result_t result;
    wt_tls_self_signed_t identity;
    wt_status_t status;
    const char *colon;
    char host[WT_LOOP_HOST_MAX];

    memset(&loop, 0, sizeof(loop));
    memset(&identity, 0, sizeof(identity));
    colon = strrchr(options.address, ':');
    if (colon == NULL || (size_t)(colon - options.address) + 1U >= sizeof(host)) {
      fprintf(stderr, "wt: the address must be host:port\n");
      return 2;
    }
    memcpy(host, options.address, (size_t)(colon - options.address));
    host[colon - options.address] = '\0';
    (void)snprintf(loop.host, sizeof(loop.host), "%s", host);
    loop.port = (uint16_t)strtoul(colon + 1, NULL, 10);
    loop.authority = options.origin != NULL ? options.origin : "localhost";
    loop.path = "/";
    loop.timeout_ms = options.timeout_ms;
    loop.datagram = options.exchange == WT_CLI_EXCHANGE_DATAGRAM;
    loop.message = options.message;
    /* An identity generated in memory for a local session: the client reaches it by pinning its fingerprint,
     * which this prints so the other side can be told what to expect. */
    status = wt_tls_self_signed_generate(&identity, "localhost");
    if (status != WT_OK) {
      fprintf(stderr, "wt: no identity could be generated: %s\n", wt_loop_status_name(status));
      return 1;
    }
    loop.identity = &identity;

    status = wt_loop_run_server(&loop, &result);
    if (options.json != 0) {
      printf("{\"role\":\"server\",\"status\":\"%s\",\"boundPort\":%u,\"established\":%s,"
             "\"connectAccepted\":%s,\"receivedBytes\":%llu,\"receivedDatagram\":%s,\"pin\":\"",
             wt_loop_status_name(status), (unsigned)result.bound_port,
             result.established != 0 ? "true" : "false",
             result.connect_accepted != 0 ? "true" : "false",
             (unsigned long long)result.received_bytes,
             result.received_datagram != 0 ? "true" : "false");
      {
        size_t pin_index;
        for (pin_index = 0U; pin_index < WT_SHA256_LEN; pin_index++) {
          printf("%02x", (unsigned)identity.fingerprint[pin_index]);
        }
      }
      /* The pin's value is closed and separated HERE, at one comma, because the fields after it were once
       * appended to a `"}` that had already closed both -- which produced `"pin":"..."closeKind":0` and a report
       * that no JSON parser would read. Every assertion here matched a substring, so nothing said so; the check
       * script validates the report as JSON now, which is what a caller parsing it does (WT-144). */
      printf("\",\"request\":\"%s\",\"requestOutcome\":%u,\"requestStatus\":%llu,\"h3Error\":%llu,"
             "\"closeKind\":%u,\"closeSentErrorCode\":%llu,\"closeSentFrameType\":%llu,\"closeCause\":\"%s\","
             "\"closeSent\":%s}\n",
             result.request_line, result.request_outcome, (unsigned long long)result.request_status,
             (unsigned long long)result.h3_error,
             result.close_kind, (unsigned long long)result.close_sent_error_code,
             (unsigned long long)result.close_sent_frame_type, wt_status_name(result.close_cause),
             result.close_was_sent != 0 ? "true" : "false");
    } else {
      printf("server: %s on port %u, received %llu byte(s)%s\n", wt_loop_status_name(status),
             (unsigned)result.bound_port, (unsigned long long)result.received_bytes,
             result.received_datagram != 0 ? " as a datagram" : " on a stream");
      /* A session this endpoint ENDED by closing is not a session that went well, so the close is reported here
       * rather than only on the failure path -- staying silent about it is how a tool printed "ok" for a run that
       * had sent CONNECTION_CLOSE (WT-144). `close_was_sent` says the peer was actually TOLD: a silent idle
       * timeout (RFC 9000 section 10.1) is a connection this endpoint stopped, not one it announced (WT-145). */
      if (result.close_was_sent != 0) {
        printf("server: THIS endpoint closed the connection with code 0x%llx, blaming frame type %llu\n",
               (unsigned long long)result.close_sent_error_code,
               (unsigned long long)result.close_sent_frame_type);
        if (result.close_cause != WT_OK) {
          printf("server: after a frame handler refused with %s\n", wt_status_name(result.close_cause));
        }
      } else if (result.close_kind != 0U) {
        printf("server: the connection was closed silently (the idle timeout; no CONNECTION_CLOSE was sent)\n");
      }
    }
    return status == WT_OK ? 0 : 1;
  }

  return wt_usage(argv[0]);
}
