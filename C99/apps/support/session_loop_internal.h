/* Declarations shared across the split session-loop translation units.
 *
 * `session_loop.c` was one file holding the two sides of a CLI session. It is now three: the shared
 * sink and pump machinery and the send helper, `session_loop_client.c` (the client's one loop) and
 * `session_loop_server.c` (the server's). Everything they share lives here -- the two loop structs,
 * the round counts the deadlines are computed from, and the prototypes of the helpers that used to be
 * `static` in the single file.
 *
 * The public header `session_loop.h` is unchanged: a caller of `wt_loop_run_client` /
 * `wt_loop_run_server` sees exactly what it saw before, and nothing here is exposed to it. */

#ifndef WT_SUPPORT_SESSION_LOOP_INTERNAL_H
#define WT_SUPPORT_SESSION_LOOP_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "session_loop.h"

#include "webtransport/http3/driver.h"
#include "webtransport/quic/connection.h"
#include "webtransport/runtime/session.h"
#include "webtransport/runtime/udp.h"
#include "webtransport/webtransport/buffered.h"

#include "capsule_stream.h"

#define WT_LOOP_ROUNDS 20000U
#define WT_LOOP_WAIT_MICROS 2000U

/* How many rounds fit in the timeout the caller asked for, at the interval each wait ACTUALLY uses.
 *
 * The deadline used to be `timeout_ms * 2U + 100U` rounds, which is a guess about the wait interval: with a
 * 2 ms wait that is four times the timeout asked for, so `--timeout-ms 5000` took twenty seconds and a client
 * pointed at a peer that never answers looked like it had hung (WT-140). The two macros are the two intervals
 * this file waits for -- `WT_LOOP_WAIT_MICROS`, and ten times that for the peer-discovery peek -- divided into
 * the timeout, so the number of rounds and the number of milliseconds agree. */
#define WT_LOOP_ROUNDS_FOR(timeout_ms) (((uint64_t)(timeout_ms) * 1000U) / (uint64_t)WT_LOOP_WAIT_MICROS)
#define WT_LOOP_PEEK_ROUNDS_FOR(timeout_ms) \
  (((uint64_t)(timeout_ms) * 1000U) / ((uint64_t)WT_LOOP_WAIT_MICROS * 10U))

typedef struct loop_side {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  uint8_t section[2048];
  size_t section_length;
  int section_complete;
  /* Set when the peer's field section did not fit `section`: the section is a bound THIS TOOL imposed, and without
   * this flag the loop below reports the same `"status":"timeout"` it reports for a peer that answered nothing. */
  int section_overflow;
  uint64_t request_stream_id;
  unsigned frames_seen;
  uint8_t data[512];
  size_t data_bytes;
  int data_was_datagram;
  /* The session and the peer's flow-control account, fed by the capsules on the CONNECT stream (WT-164). The
   * walking and the byte-keeping are `apps/support/capsule_stream.c`, shared with the conformance tool so that
   * "the session's capsules" means one thing in both. */
  wt_capsule_stream_t capsules;
  /* What a refused capsule is stated TO. The sink runs inside the driver's routing, so a refusal has to be
   * expressed while it is being made: an HTTP/3 error goes to the connection, a session error into a close capsule
   * on `request_stream_id`, which is why the transport is here as well (WT-165). Both are set once by the side's
   * own setup, because the loop they belong to is created after this struct is. */
  const wt_http3_driver_transport_t *transport;
  wt_quic_connection_t *connection;
  uint64_t now_for_close;
  /* Whether this endpoint knows which session it is serving -- the client from the moment it starts one, the
   * server from the moment it accepts the CONNECT. Until then a stream or datagram cannot be associated, so it
   * is parked by the LIBRARY's section 4.6 buffer and drained when the ID becomes known: the ones that name this
   * session are delivered, the rest are dropped. That object owns both halves of the rule and its bounds (WT-180);
   * this side owns only the memory a datagram's payload is copied into. */
  int session_known;
  wt_webtransport_buffered_t buffered;
  /* The HTTP/3 code of the last capsule refusal, for the report: a run that closed the connection should say which
   * rule it closed it over (WT-165). */
  uint64_t capsule_error;
} loop_side_t;

typedef struct loop {
  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  wt_runtime_session_t session;
  loop_side_t side;
  /* The transport the driver sends through, kept here because the lost-frame handler needs it: a report of a
   * lost frame arrives long after the call that built the transport returned (WT-135). */
  wt_http3_driver_transport_t transport;
  /* How many times a lost-frame report was answered by sending the request again: the counter that says whether
   * the retransmission path RAN, which reading the code cannot (WT-135). */
  unsigned resends;
  uint64_t now;
} loop_t;

/* The helpers the three translation units share. They lost `static` when the file became three; a
 * future reader must not tighten one back without moving its callers too. */
void init_side(loop_side_t *side, wt_http3_role_t role);
void side_session_known(loop_side_t *side);
wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);
uint64_t build_parameters(uint8_t *out, size_t capacity, int is_server, const uint8_t *source,
                          size_t source_length, const uint8_t *original_destination,
                          size_t original_length, int retried, const uint8_t *retry_source,
                          size_t retry_source_length);
void connection_config(wt_quic_connection_config_t *config, wt_quic_role_t role,
                       const uint8_t *connection_id, size_t connection_id_length);
void client_on_lost_frame(void *context, const wt_quic_tx_frame_t *frame);
int handshake_ready(const loop_t *loop);
wt_status_t loop_close_status(const loop_t *loop);
int loop_is_closed(const loop_t *loop);
wt_status_t loop_wait_status(const loop_t *loop);
void record_oracle(const loop_t *loop, wt_loop_result_t *out);
void pump_once(loop_t *loop);
wt_status_t send_message(loop_t *loop, const wt_http3_driver_transport_t *transport,
                         const wt_loop_config_t *config);

#endif /* WT_SUPPORT_SESSION_LOOP_INTERNAL_H */
