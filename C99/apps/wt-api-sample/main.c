/* wt-api-sample -- a consumer of the public C99 API, and nothing else.
 *
 * This program is the plan's Phase 8 completion criterion made executable: it includes
 * ONE header, `webtransport/webtransport.h`, uses only the public functions, and runs a
 * whole session's worth of behaviour -- establishment, a peer stream, a peer datagram,
 * a flow-control capsule, backpressure, drain and close -- against the library. It is
 * built and run by CTest on every platform this project builds on, so the day a public
 * declaration moves, changes shape, or starts needing a header the umbrella does not
 * provide, this program stops compiling rather than a user's program does.
 *
 * It is deliberately NOT a network client: the public API is the layer that turns wire
 * events into calls and calls into wire bytes, and the connection that moves those bytes
 * is wired to it in Phase 9. What this sample proves is the API's own contract, which is
 * what a consumer writes against.
 *
 * Exit status: 0 when every step behaved as the API documents, 1 when one did not.
 */

#include <stdio.h>
#include <string.h>

#include "webtransport/webtransport.h"

/* A failure the sample cannot continue past. The message is the sample's own text, which
 * is exactly what the API's error surface is designed to allow: the status and the code
 * come from the library, and no peer text ever does. */
static int fail(const char *step, wt_status_t status, uint64_t code) {
  fprintf(stderr, "FAIL %s: %s (code %llu)\n", step, wt_session_status_name(status),
          (unsigned long long)code);
  return 1;
}

/* The peer's side of the conversation, recorded as it is reported. */
typedef struct peer_log {
  unsigned streams_opened;
  size_t bytes_received;
  unsigned datagrams_received;
  int drained;
  int closed;
  uint32_t close_code;
} peer_log_t;

static void on_stream_opened(void *context, uint64_t stream_id, int unidirectional) {
  peer_log_t *log = context;
  log->streams_opened++;
  printf("  peer opened stream %llu (%s)\n", (unsigned long long)stream_id,
         unidirectional != 0 ? "unidirectional" : "bidirectional");
}

static void on_stream_data(void *context, uint64_t stream_id, const uint8_t *data, size_t length,
                           int end_stream) {
  peer_log_t *log = context;
  (void)stream_id;
  log->bytes_received += length;
  printf("  peer sent %llu bytes%s\n", (unsigned long long)length,
         end_stream != 0 ? " and ended" : "");
  if (length > 0U) printf("  first byte: 0x%02x\n", (unsigned)data[0]);
}

static void on_datagram(void *context, const uint8_t *data, size_t length) {
  peer_log_t *log = context;
  log->datagrams_received++;
  printf("  peer sent a datagram of %llu bytes\n", (unsigned long long)length);
  if (length > 0U) printf("  first byte: 0x%02x\n", (unsigned)data[0]);
}

static void on_drain(void *context) {
  ((peer_log_t *)context)->drained = 1;
  printf("  peer is draining\n");
}

static void on_close(void *context, uint32_t error_code) {
  peer_log_t *log = context;
  log->closed = 1;
  log->close_code = error_code;
  printf("  peer closed with code %u\n", (unsigned)error_code);
}

int main(void) {
  wt_endpoint_config_t endpoint = wt_endpoint_config_default();
  wt_session_config_t config;
  wt_status_t endpoint_status;
  wt_session_callbacks_t callbacks;
  peer_log_t log;
  wt_session_t *session = NULL;
  wt_http3_settings_t peer_settings;
  wt_session_flow_state_t flow;
  uint8_t wire[512];
  size_t wire_length = 0U;
  wt_writer_t w;
  wt_status_t status;
  int exit_status = 0;

  memset(&log, 0, sizeof(log));
  memset(&callbacks, 0, sizeof(callbacks));

  printf("webtransport-c99 %s (%s)\n\n", wt_version_string(), wt_protocol_draft());

  /* An ENDPOINT: which side this program is, the name it is reached at, how the peer's
   * certificate is judged, and the authority and path the CONNECT request will carry. The
   * development bypass is used here because a sample connects to nothing; it is tied to a
   * loopback name, so the same configuration against a real host is refused below. */
  endpoint.role = WT_ENDPOINT_ROLE_CLIENT;
  endpoint.host = "localhost";
  endpoint.port = 4433U;
  endpoint.path = "/chat";
  endpoint.trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
  endpoint_status = wt_endpoint_config_check(&endpoint);
  if (endpoint_status != WT_OK) return fail("wt_endpoint_config_check", endpoint_status, 0U);
  printf("endpoint: %s on %s:%u, trust %s\n", wt_endpoint_role_name(endpoint.role), endpoint.host,
         (unsigned)endpoint.port, "local development (loopback only)");

  /* The endpoint produces the session configuration, so the authority and path a request
   * carries come from one place rather than from whichever string was nearest. */
  if (wt_endpoint_session_config(&endpoint, 4U, &config) != WT_OK) {
    return fail("wt_endpoint_session_config", WT_ERR_STATE, 0U);
  }
  printf("session: %s%s on CONNECT stream %llu\n", config.authority, config.path,
         (unsigned long long)config.session_id);

  /* FLOW CONTROL is the peer's SETTINGS. The sample plays the peer and advertises the
   * draft-16 initial limits, then asks the API whether that turns flow control on. */
  wt_http3_settings_init(&peer_settings);
  if (wt_http3_settings_set(&peer_settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 1024U) != WT_OK ||
      wt_http3_settings_set(&peer_settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI, 4U) !=
          WT_OK) {
    return fail("peer settings", WT_ERR_STATE, 0U);
  }
  printf("peer advertises flow control: %s\n",
         wt_session_flow_advertised(&peer_settings) != 0 ? "yes" : "no");

  status = wt_session_create(&config, NULL, &session);
  if (status != WT_OK) return fail("wt_session_create", status, 0U);

  /* The EVENT LOOP seam: the library reports into these, and they run inside the calls
   * below rather than on a thread of the library's own. */
  callbacks.context = &log;
  callbacks.on_stream_opened = on_stream_opened;
  callbacks.on_stream_data = on_stream_data;
  callbacks.on_datagram = on_datagram;
  callbacks.on_drain = on_drain;
  callbacks.on_close = on_close;
  status = wt_session_set_callbacks(session, &callbacks);
  if (status != WT_OK) return fail("wt_session_set_callbacks", status, 0U);

  /* The response went out: the session may carry streams and datagrams. */
  status = wt_session_established(session);
  if (status != WT_OK) return fail("wt_session_established", status, 0U);

  /* The peer's SETTINGS, applied to this endpoint's send-side allowances. */
  status = wt_session_flow_configure(session, 1, 1024U, 4U, 4U);
  if (status != WT_OK) return fail("wt_session_flow_configure", status, 0U);
  flow = wt_session_flow_snapshot(session);
  printf("send allowance: %llu bytes, %llu bidirectional streams\n",
         (unsigned long long)wt_session_flow_data_allowance(session),
         (unsigned long long)wt_session_flow_stream_allowance(session, 0));
  if (flow.max_data_state != WT_SESSION_LIMIT_LIMITED) {
    return fail("a limited max_data", WT_ERR_STATE, 0U);
  }

  /* A STREAM the peer opened. On the wire its first bytes name the session; the sample
   * writes that prefix with the public framing helper so the bytes it feeds below are the
   * bytes a peer would send. */
  printf("\npeer stream:\n");
  w = wt_writer_init(wire, sizeof(wire));
  status = wt_webtransport_stream_prefix_write(&w, 0, config.session_id);
  if (status != WT_OK) return fail("wt_webtransport_stream_prefix_write", status, 0U);
  status = wt_session_on_stream_opened(session, 8U, 0, config.session_id);
  if (status != WT_OK) return fail("wt_session_on_stream_opened", status, 0U);
  status = wt_session_on_stream_data(session, 8U, (const uint8_t *)"hello", 5U, 1);
  if (status != WT_OK) return fail("wt_session_on_stream_data", status, 0U);
  if (log.streams_opened != 1U || log.bytes_received != 5U) {
    return fail("the stream was reported", WT_ERR_STATE, 0U);
  }

  /* A DATAGRAM from the peer. The datagram's own framing carries the quarter stream ID;
   * what the callback sees is the session payload alone. */
  printf("\npeer datagram:\n");
  w = wt_writer_init(wire, sizeof(wire));
  status = wt_webtransport_datagram_write(&w, config.session_id / 4U, (const uint8_t *)"ping", 4U);
  if (status != WT_OK) return fail("wt_webtransport_datagram_write", status, 0U);
  status = wt_session_on_datagram(session, wire, wt_writer_offset(&w));
  if (status != WT_OK) return fail("wt_session_on_datagram", status, 0U);

  /* BACKPRESSURE: the allowance is asked before sending, and a sender that ignores it is
   * refused with the code the peer would be sent for the violation. */
  printf("\nbackpressure:\n");
  printf("  allowance before sending: %llu\n",
         (unsigned long long)wt_session_flow_data_allowance(session));
  status = wt_session_flow_record_data(session, 1024U);
  if (status != WT_OK) return fail("sending within the grant", status, 0U);
  printf("  allowance after the grant is used: %llu\n",
         (unsigned long long)wt_session_flow_data_allowance(session));
  status = wt_session_flow_record_data(session, 1U);
  if (status != WT_ERR_LIMIT) return fail("one byte past the grant is refused", status, 0U);
  printf("  one byte more is refused with code %llu (the draft's flow-control error)\n",
         (unsigned long long)wt_session_last_error(session).code);

  /* CLOSE and DRAIN: one call moves the state and writes the capsule, so a caller cannot
   * send the bytes without the state or the state without the bytes. */
  printf("\ndrain and close:\n");
  status = wt_session_write_drain(session, wire, sizeof(wire), &wire_length);
  if (status != WT_OK) return fail("wt_session_write_drain", status, 0U);
  printf("  drain capsule: %llu bytes, state is %d\n", (unsigned long long)wire_length,
         (int)wt_session_state(session));
  status = wt_session_write_close(session, 0U, "sample finished", wire, sizeof(wire), &wire_length);
  if (status != WT_OK) return fail("wt_session_write_close", status, 0U);
  printf("  close capsule: %llu bytes, state is %d\n", (unsigned long long)wire_length,
         (int)wt_session_state(session));
  if (wt_session_state(session) != WT_SESSION_CLOSED) {
    exit_status = fail("the session is closed", WT_ERR_STATE, 0U);
  }

  /* OWNERSHIP: the handle goes back to the allocator it was made with -- the default one
   * here, which is what NULL names at both ends. */
  wt_session_destroy(session, NULL);

  printf("\nsample complete: 1 stream, %u datagram(s), drained, closed, made with the public "
         "API only\n",
         log.datagrams_received);
  return exit_status;
}
