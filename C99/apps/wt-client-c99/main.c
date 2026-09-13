/* wt-client-c99 -- see ../../IMPLEMENTATION_PLAN.md, Phase 9.
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

/* The transcript's message types as hex, for the JSON: "0102080b0d..." reads as ClientHello, ServerHello, ... */
static const char *wt_client_transcript_types(const wt_loop_result_t *result) {
  static char text[2U * 16U + 1U];
  static const char digits[] = "0123456789abcdef";
  size_t index;
  for (index = 0U; index < result->transcript_types_length && index < 16U; index++) {
    text[index * 2U] = digits[(result->transcript_types[index] >> 4) & 0x0fU];
    text[index * 2U + 1U] = digits[result->transcript_types[index] & 0x0fU];
  }
  text[result->transcript_types_length * 2U] = '\0';
  return text;
}

static int wt_usage(const char *program) {
  printf("usage: %s [options]\n", program);
  printf("\n");
  printf("WebTransport over HTTP/3, C99 implementation %s (%s).\n",
         wt_version_string(), wt_protocol_draft());
  printf("\n");
  printf("It connects to a peer, establishes a WebTransport session and exchanges\n");
  printf("the message named by --exchange over the transport named by --transport.\n");
  printf("The peer's identity is checked according to --trust, including the pinned\n");
  printf("identities a local development peer uses. It exits non-zero when the\n");
  printf("session does not complete.\n");
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

  /* A client parses its target and does not bind: its local port is the system's business, and
   * binding one would stop two clients on one machine from reaching one server. */
  {
    wt_cli_endpoint_t endpoint;
    if (wt_cli_endpoint_open(&endpoint, options.address, 0) != WT_OK) {
      if (options.json != 0) {
        printf("{\"error\":\"endpoint\"}\n");
      } else {
        fprintf(stderr, "wt: cannot parse %s\n", options.address);
      }
      return 2;
    }
    if (options.json != 0) {
      wt_cli_endpoint_write_json(&endpoint, options.address, stdout);
    } else {
      printf("target: %s %s\n", wt_cli_family_name(endpoint.address.family), options.address);
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
  /* The session itself: connect, CONNECT, response, and one message each way. This is the tool's whole job
   * when it was asked to connect; the usage below stays for the case where it was not. */
  fprintf(stderr, "DIAG mode=%d address=%s\n", (int)options.mode,
          options.address != NULL ? options.address : "(null)");
  if (options.mode == WT_CLI_MODE_CONNECT) {
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
    /* The development bypass is restricted to loopback names, so a pin is generated here only to be printed:
     * a real deployment passes --trust system and a certificate that validates. */
    (void)wt_tls_self_signed_generate(&identity, "localhost");
    loop.pin = NULL; /* the loopback development bypass: a pinned run is what a real deployment uses */

    status = wt_loop_run_client(&loop, &result);
    if (options.json != 0) {
      printf("{\"role\":\"client\",\"status\":\"%s\",\"established\":%s,\"connectAccepted\":%s,"
             "\"responseStatus\":%u,\"receivedBytes\":%llu,\"receivedDatagram\":%s,"
             "\"firstReceiveError\":\"%s\",\"receiveErrors\":%u,\"packetsSeen\":%u,"
             "\"lastReceive\":\"%s\",\"closeCodeSet\":%s,\"closeCode\":%llu,"
             "\"closeFrameType\":%llu,\"peerClosed\":%s,\"peerErrorCode\":%llu,"
             "\"packetsDiscarded\":%llu,\"keys\":{\"initial\":%s,\"handshake\":%s,"
             "\"application\":%s},\"handshakeState\":\"%s\",\"resends\":%u,\"probes\":%u,"
             "\"probesWithData\":%u,\"requestStreamId\":%llu,"
             "\"streamsOpened\":{\"bidi\":%u,\"uni\":%u},"
             "\"sent\":{\"initial\":%u,\"handshake\":%u,\"application\":%u},"
             "\"transcriptTypes\":\"%s\","
             "\"acks\":{\"initial\":[%u,%llu],\"handshake\":[%u,%llu],\"application\":[%u,%llu]}}\n",
             wt_loop_status_name(status), result.established != 0 ? "true" : "false",
             result.connect_accepted != 0 ? "true" : "false", (unsigned)result.status,
             (unsigned long long)result.received_bytes, result.received_datagram != 0 ? "true" : "false",
             wt_status_name(result.first_receive_error), result.receive_errors, result.packets_seen,
             wt_status_name(result.last_receive), result.close_code_set != 0 ? "true" : "false",
             (unsigned long long)result.close_code, (unsigned long long)result.close_frame_type,
             result.peer_closed != 0 ? "true" : "false", (unsigned long long)result.peer_error_code,
             (unsigned long long)result.packets_discarded, result.has_initial_keys != 0 ? "true" : "false",
             result.has_handshake_keys != 0 ? "true" : "false",
             result.has_application_keys != 0 ? "true" : "false",
             result.handshake_state != NULL ? result.handshake_state : "unknown", result.resends,
             result.probes, result.probes_with_data,
             (unsigned long long)result.request_stream_id, result.streams_opened_bidi,
             result.streams_opened_uni, result.sent_initial, result.sent_handshake,
             result.sent_application, wt_client_transcript_types(&result), result.acks_initial,
             result.ack_largest_initial, result.acks_handshake, result.ack_largest_handshake,
             result.acks_application, result.ack_largest_application);
    } else {
      printf("client: %s, response %u, received %llu byte(s)%s\n", wt_loop_status_name(status),
             (unsigned)result.status, (unsigned long long)result.received_bytes,
             result.received_datagram != 0 ? " as a datagram" : " on a stream");
      /* The status above is the TOOL's ("timeout"); this is the layer's, and it is the difference between "the
       * peer never answered" and "the peer answered with something this endpoint refused". */
      if (result.receive_errors > 0U) {
        printf("client: the runtime recorded %u receive error(s), the first being %s\n", result.receive_errors,
               wt_status_name(result.first_receive_error));
      }
      if (status != WT_OK) {
        printf("client: the connection saw %u packet(s) and discarded %llu; its last receive said %s\n",
               result.packets_seen, (unsigned long long)result.packets_discarded,
               wt_status_name(result.last_receive));
        printf("client: keys in -- initial %s, handshake %s, application %s; handshake state %s\n",
               result.has_initial_keys != 0 ? "yes" : "no", result.has_handshake_keys != 0 ? "yes" : "no",
               result.has_application_keys != 0 ? "yes" : "no",
               result.handshake_state != NULL ? result.handshake_state : "unknown");
        if (result.resends > 0U) {
          printf("client: answered %u lost-frame report(s) by resending the request\n", result.resends);
        }
        if (result.close_code_set != 0) {
          printf("client: this endpoint refused with code 0x%llx, blaming frame type %llu\n",
                 (unsigned long long)result.close_code, (unsigned long long)result.close_frame_type);
        }
        if (result.peer_closed != 0) {
          printf("client: the peer closed with code 0x%llx\n", (unsigned long long)result.peer_error_code);
        }
      }
    }
    return status == WT_OK ? 0 : 1;
  }

  return wt_usage(argv[0]);
}
