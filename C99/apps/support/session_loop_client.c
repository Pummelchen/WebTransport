/* The CLIENT half of the one-sided session loops (Phase 9): `wt_loop_run_client`.
 *
 * Connect, send the CONNECT, wait for the response, and exchange one message. The sink, the pump
 * and every helper it uses are in `session_loop.c`, declared by "session_loop_internal.h". */

#include "session_loop.h"

#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>
#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/server_retry.h"
#include "webtransport/runtime/session.h"
#include "webtransport/webtransport/buffered.h"
#include "webtransport/webtransport/error.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

#include "capsule_stream.h"

#include "session_loop_internal.h"

wt_status_t wt_loop_run_client(const wt_loop_config_t *config, wt_loop_result_t *out) {
  static const uint8_t k_connection_id[8] = {0x11U, 0x22U, 0x33U, 0x44U,
                                             0x55U, 0x66U, 0x77U, 0x88U};
  loop_t loop;
  uint8_t parameters[256];
  uint64_t parameters_len;
  wt_quic_connection_config_t connection;
  wt_tls_client_config_t tls;
  wt_http3_settings_t settings;
  wt_http3_message_t response;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_udp_address_t peer;
  uint8_t scratch[1024];
  uint64_t deadline_rounds;
  unsigned round;

  if (config == NULL || out == NULL || config->authority == NULL || config->path == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(out, 0, sizeof(*out));
  memset(&loop, 0, sizeof(loop));
  loop.now = 1000U;
  /* No Retry on this path (WT-168 is the round that will add one), so `retried` is 0 and the retry source is
   * absent -- which the builder refuses to accept the other way round. */
  parameters_len = build_parameters(parameters, sizeof(parameters), 0, k_connection_id,
                                   sizeof(k_connection_id), NULL, 0U, 0, NULL, 0U);
  if (parameters_len == 0U) return WT_ERR_LIMIT;

  {
    /* The caller gives a host and a port separately; the runtime parses one string, so they are joined here
     * rather than in every caller. */
    char joined[WT_LOOP_HOST_MAX + 16U];
    (void)snprintf(joined, sizeof(joined), "%s:%u", config->host, (unsigned)config->port);
    if (wt_udp_address_parse_host_port(joined, &peer) != WT_OK) return WT_ERR_INVALID_ARGUMENT;
  }
  if (wt_udp_socket_open(&loop.socket, peer.family) != WT_OK) return WT_ERR_IO;
  loop.peer = peer;

  connection_config(&connection, WT_QUIC_ROLE_CLIENT, k_connection_id, sizeof(k_connection_id));
  memset(&tls, 0, sizeof(tls));
  {
    static const char *const alpn_h3[] = {"h3"};
    tls.alpn = alpn_h3;
    tls.alpn_count = 1U;
  }
  tls.host_name = config->authority;
  tls.require_transport_parameters = 1;
  tls.transport_parameters = parameters;
  tls.transport_parameters_len = (size_t)parameters_len;
  if (config->pin != NULL) {
    tls.trust.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
    tls.trust.host_name = config->authority;
    memcpy(tls.trust.fingerprints[0], config->pin, WT_SHA256_LEN);
    tls.trust.fingerprint_count = 1U;
  } else if (config->trust == (int)WT_TLS_TRUST_SYSTEM) {
    /* Validated against the platform trust store, AND the name in `authority` is checked as part of that
     * validation, so a chain that is valid for a different host is refused. The CLI's own default is this mode,
     * and it used to be accepted, echoed in the report as `"trust":"system"` and then ignored in favour of the
     * bypass below -- a caller who asked for verification got none (WT-193). */
    tls.trust.mode = WT_TLS_TRUST_SYSTEM;
    tls.trust.host_name = config->authority;
  } else {
    /* The development bypass, which the trust layer restricts to loopback names. */
    tls.trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
    tls.trust.host_name = config->authority;
  }

  {
    wt_status_t status = wt_runtime_session_start_client(&loop.session, &loop.socket, &peer,
                                                         k_connection_id, sizeof(k_connection_id),
                                                         &connection, &tls, loop.now);
    if (status != WT_OK) {
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  /* A DIAGNOSTIC, and only a diagnostic: with WT_TLS_SECRET_LOG set, this client appends its own
   * CLIENT_HANDSHAKE_TRAFFIC_SECRET to that file in the NSS keylog format, so that a peer which writes the same
   * line can be compared value for value. It exists because a third-party peer could not decrypt this client's
   * Finished while this client decrypted the peer's (WT-135), and no amount of reading the derivation could say
   * which of the two values was wrong. Never set in production; the file holds a traffic secret. */
  {
    const char *keylog_path = getenv("WT_TLS_SECRET_LOG");
    if (keylog_path != NULL) {
      FILE *keylog = fopen(keylog_path, "a");
      if (keylog != NULL) {
        unsigned index;
        fprintf(keylog, "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00");
        for (index = 0U; index < WT_TLS13_SECRET_LEN; index++) {
          fprintf(keylog, "%02x", loop.session.handshake.client.client_handshake_secret[index]);
        }
        fprintf(keylog, "\n");
        (void)fclose(keylog);
      }
    }
  }

  /* The advertised limits, in force: the promise and the enforcement in one place. */
  (void)wt_runtime_session_advertise(&loop.session, 100000U, 4096U, 8U, 8U);
  /* And one spare connection ID kept out there (WT-171), so a peer that retires one is answered with a
   * replacement instead of talking to an endpoint that runs out. */
  (void)wt_runtime_session_keep_spare_connection_id(&loop.session);
  init_side(&loop.side, WT_HTTP3_ROLE_CLIENT);
  (void)wt_runtime_session_set_frame_handler(&loop.session, side_on_frame, &loop.side);
  wt_http3_driver_quic_transport(&loop.session.connection, &loop.transport);
  /* What a refused capsule is stated to (WT-165), and the clock it is stated at. */
  loop.side.transport = &loop.transport;
  loop.side.connection = &loop.session.connection;
  loop.side.now_for_close = loop.now;
  /* Bound so that a refusal with an HTTP/3 error reaches the peer as an application close (WT-159). */
  wt_http3_driver_bind_connection(&loop.side.driver, &loop.session.connection);
  (void)wt_runtime_session_set_lost_frame_handler(&loop.session, client_on_lost_frame, &loop);
  /* The client chose the CONNECT stream, so it knows its session's ID from here: a datagram naming it is
   * associable even before the response arrives, and one naming anything else is the error section 4.2 covers. */
  side_session_known(&loop.side);

  deadline_rounds = WT_LOOP_ROUNDS_FOR(config->timeout_ms);
  if (deadline_rounds > WT_LOOP_ROUNDS) deadline_rounds = WT_LOOP_ROUNDS;

  for (round = 0U; round < deadline_rounds && handshake_ready(&loop) == 0 && loop_is_closed(&loop) == 0;
       round++) {
    pump_once(&loop);
  }
  if (handshake_ready(&loop) == 0) {
    record_oracle(&loop, out);
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return loop_is_closed(&loop) != 0 ? loop_wait_status(&loop) : WT_ERR_TIMEOUT;
  }
  out->established = 1;

  /* The client's SETTINGS, from the one place that owns them: section 3.1 requires SETTINGS_H3_DATAGRAM and the
   * draft-specific codepoint, and the set also carries the enabling codepoints of the earlier drafts, which is
   * how section 7.1 negotiates with a peer that predates the rename (WT-145). */
  wt_http3_settings_init(&settings);
  {
    wt_status_t status = wt_webtransport_settings_apply(&settings, 0);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  /* Which `:protocol` token the CONNECT below carries. The caller's configuration says so because the token
   * cannot be negotiated: a peer written against a pre-rename draft knows only `webtransport` and refuses the
   * extended CONNECT with H3_MESSAGE_ERROR before any SETTINGS exchange. 0 is the draft-16 default, which is
   * what the library sends unless this is overridden (F-02b). */
  wt_http3_driver_set_upgrade_token(&loop.side.driver, (wt_webtransport_upgrade_token_t)config->upgrade_token);
  /* The request stream is opened and the session ID is known, but the CONNECT has not been sent: this is the
   * window section 4.6 is about, and `--early-stream` is what puts a message in it (WT-189). */
  {
    wt_status_t status = wt_http3_driver_open_session_stream(&loop.side.driver, &loop.transport, &settings,
                                                             loop.now, &loop.side.request_stream_id,
                                                             &h3_error);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  if (config->early_stream != 0) {
    wt_status_t status = send_message(&loop, &loop.transport, config);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
    out->early_stream_sent = 1;
  }
  {
    wt_status_t status = wt_http3_driver_send_session_request(&loop.side.driver, &loop.transport,
                                                              loop.side.request_stream_id, config->authority,
                                                              config->path, 0U, loop.now, &h3_error);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  for (round = 0U; round < deadline_rounds && loop.side.section_complete == 0 && loop_is_closed(&loop) == 0;
       round++) {
    pump_once(&loop);
  }
  if (loop.side.section_complete == 0) {
    record_oracle(&loop, out);
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    if (loop.side.section_overflow != 0) {
      /* The response WAS refused, and by this tool's bound rather than by the peer: saying so is the difference
       * between "the peer never answered" and "the answer did not fit", which is the distinction WT-155 added
       * `responseOutcome` for. No HTTP/3 error code goes with it, because the peer broke no rule. */
      out->response_outcome = (unsigned)WT_LOOP_RESPONSE_REFUSED;
      return WT_ERR_LIMIT;
    }
    return loop_is_closed(&loop) != 0 ? loop_wait_status(&loop) : WT_ERR_TIMEOUT;
  }
  {
    wt_status_t status = wt_http3_endpoint_on_response_headers(
        &loop.side.endpoint, loop.side.request_stream_id, loop.side.section, loop.side.section_length,
        scratch, sizeof(scratch), &response, &h3_error);
    if (status != WT_OK) {
      /* WHY the response did not become a session, which is the whole point of the field set (WT-155): before
       * this, a peer that answered a field section this layer refused and a peer that answered nothing both
       * produced `"status":"timeout"` from the tool. */
      out->response_outcome = (unsigned)WT_LOOP_RESPONSE_REFUSED;
      out->h3_error = (uint64_t)h3_error;
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
    out->connect_accepted = response.has_status != 0 && response.status >= 200U && response.status < 300U;
    out->response_outcome = out->connect_accepted != 0 ? (unsigned)WT_LOOP_RESPONSE_ACCEPTED
                                                       : (unsigned)WT_LOOP_RESPONSE_NOT_ACCEPTED;
    out->status = (uint32_t)response.status;
    /* The response establishes the session (section 3.1). The CONNECT stream was marked as a capsule stream by
     * `start_session`, and this response is the one HTTP/3 frame that mark was waiting for -- so the peer's
     * capsules are walked from here on (WT-164). */
    if (out->connect_accepted != 0) wt_capsule_stream_established(&loop.side.capsules);
  }

  if (config->early_stream == 0) {
    wt_status_t status = send_message(&loop, &loop.transport, config);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  /* Give the peer a moment to receive it and to answer with its own message where it has one. */
  for (round = 0U; round < 200U && loop.side.data_bytes == 0U; round++) pump_once(&loop);
  out->received_bytes = loop.side.data_bytes;
  out->received_datagram = loop.side.data_was_datagram;

  record_oracle(&loop, out);
  {
    /* Read BEFORE the clear, and reported instead of `WT_OK`: a run that closed the connection did not succeed. */
    wt_status_t closed = loop_close_status(&loop);
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return closed;
  }
}
