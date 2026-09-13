/* A packet session: a socket, a QUIC connection and a TLS handshake, driven together (Phase 9).
 *
 * Every piece of a WebTransport client or server already exists in this library and none of them knows
 * about the others: the connection needs somewhere to send, the handshake needs a connection with
 * Initial keys, the socket needs a caller to pump it. This is that caller, and it is deliberately the
 * ONLY place where the three meet -- so a test can stand up two of them over loopback, and so a caller
 * that wants to drive the layers itself still can.
 *
 * The rules it encodes are the ones that are easy to get wrong once and hard to see afterwards:
 *
 *   - THE INITIAL KEYS COME FROM THE DESTINATION CONNECTION ID, both directions, and the `from_server`
 *     flag is the OPPOSITE for this endpoint's receive direction. Getting that backwards produces a
 *     connection that encrypts and decrypts nothing, which looks like a peer that never answers.
 *
 *   - THE HANDSHAKE HANDLER IS CHAINED, not replaced: it returns WT_OK for every frame that is not its
 *     business, so the HTTP/3 layer's handler can be installed behind it. This session installs only the
 *     handshake for now, and `wt_runtime_session_set_frame_handler` is how the next layer joins it.
 *
 *   - THE PEER'S TRANSPORT PARAMETERS BECOME THE CONNECTION'S LIMITS, as soon as the handshake has them.
 *     Nothing else does it: the handshake carries the bytes, and a connection whose limits were never
 *     applied refuses its own HTTP/3 streams -- which presents as a state error from an open call rather
 *     than as a missing step, and cost this phase a debugging round.
 *
 *   - A PUMP IS BOUNDED. `wt_runtime_session_pump` reads what is there, flushes what is owed and
 *     returns; it never waits, because a tool that waited inside a library call could not honour its own
 *     `--timeout-ms` and could not be interrupted. The caller owns the clock and passes `now`.
 */

#ifndef WEBTRANSPORT_RUNTIME_SESSION_H
#define WEBTRANSPORT_RUNTIME_SESSION_H

#include <stdint.h>

#include "webtransport/quic/connection.h"
#include "webtransport/quic/handshake.h"
#include "webtransport/runtime/udp.h"
#include "webtransport/status.h"
#include "webtransport/tls/session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_runtime_session {
  wt_quic_connection_t connection;
  wt_quic_handshake_t handshake;
  /* Borrowed: the caller owns the socket and the address, because a test binds them and a tool closes
   * them, and an object that owned them would have to decide when. */
  const wt_udp_socket_t *socket;
  wt_udp_address_t peer;
  int is_client;
  int started;
  /* What the pump has seen, for a caller that logs or asserts: packets that were there to read and
   * rounds in which something was flushed. */
  unsigned packets_seen;
  unsigned flushes;
  /* Whether the peer's transport parameters have become this connection's limits. The handshake carries
   * them; a connection whose limits were never applied refuses the streams HTTP/3 must open before it can
   * send anything, and the refusal looks like a state error rather than a missing step. */
  int peer_parameters_applied;
  /* What the last flush SAID. A pump that discarded it could not tell "nothing to send" from "refused to
   * send", and this session spent three rounds unable to see the difference -- so the status is kept and
   * reported rather than swallowed. */
  wt_status_t last_flush;
  wt_status_t last_receive;
  /* Receives that failed for a reason that is NEITHER "nothing there" nor success: a packet that arrived
   * and was refused, which a pump that only counts successes cannot see. */
  unsigned receive_errors;
  wt_status_t first_receive_error;
  /* The layer behind the handshake, if one was installed: a function pointer and its context, because
   * the only thing that varies between "no next layer yet" and the HTTP/3 driver is which function. */
  wt_status_t (*next_handler)(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);
  void *next_context;
} wt_runtime_session_t;

/* A RULE THE CALLER MUST KEEP, and the one that cost this phase several rounds: the connection-level
 * receive credit is the ENFORCEMENT of the `initial_max_data` the endpoint ADVERTISES in its transport
 * parameters, and nothing pairs the two. A connection whose flow account was never granted starts at zero,
 * so the FIRST stream frame it receives is refused as FLOW_CONTROL_ERROR (transport code 3, frame type 8)
 * and the connection closes -- which presents as a peer that says nothing, not as a missing grant. Call
 * `wt_quic_connection_set_max_data(connection, <the value you advertised>)` before any peer stream can
 * arrive; the same is true per stream through the connection's `local_max_stream_data`, and for stream
 * COUNTS through `wt_quic_connection_set_max_streams`. Pairing them automatically is a task on the tracker
 * (it needs the advertised parameters, which this driver does not see). */
/* Put the limits this endpoint ADVERTISED in its transport parameters into force.
 *
 * It exists because the two halves must agree and nothing paired them: the advertised `initial_max_data` is a
 * promise and `wt_quic_connection_set_max_data` is the enforcement, so an endpoint that advertised a limit and
 * granted nothing refused the FIRST stream frame it received as FLOW_CONTROL_ERROR and closed the connection --
 * which presents as a peer that says nothing rather than as a missing grant (WT-110's root cause, found after
 * several rounds of measurement). Calling this once, after starting a session, moves the pairing into the
 * driver instead of leaving it in every caller's memory.
 *
 * It is a separate call rather than more parameters on `start_client`/`start_server` so that a caller's
 * arguments cannot drift out of order: four more numbers on a call that already takes seven is a mistake
 * waiting for a tired afternoon. Calling it twice is not an error -- the values are monotonic limits -- and a
 * caller that advertises nothing simply does not call it (WT-113). */
wt_status_t wt_runtime_session_advertise(wt_runtime_session_t *session, uint64_t initial_max_data,
                                         uint64_t initial_max_stream_data,
                                         uint64_t initial_max_streams_bidi,
                                         uint64_t initial_max_streams_uni);

typedef wt_status_t (*wt_runtime_frame_handler_fn)(void *context, wt_quic_space_t space,
                                                   const wt_quic_frame_t *frame);

/* Start a client: the connection is initialised, attached to its socket and peer, given its Initial
 * keys in both directions, and the TLS ClientHello is built into the Initial space. The peer's address
 * must be the one the packets go to; the socket's own family decides the wire. */
wt_status_t wt_runtime_session_start_client(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_client_config_t *tls_config, uint64_t now);

/* Start a server. Nothing is sent until a ClientHello arrives, so this only arms the endpoint. */
wt_status_t wt_runtime_session_start_server(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_server_config_t *tls_config, uint64_t now);

/* Install a handler behind the handshake's, for the layer that owns frames it does not. */
wt_status_t wt_runtime_session_set_frame_handler(wt_runtime_session_t *session,
                                                 wt_runtime_frame_handler_fn handler,
                                                 void *context);

/* Read what is there, drive the handshake and flush what is owed. Never blocks. Returns WT_OK when the
 * round completed, whatever it contained. */
wt_status_t wt_runtime_session_pump(wt_runtime_session_t *session, uint64_t now);

/* Whether the handshake is confirmed, and why it failed if it did. */
int wt_runtime_session_established(const wt_runtime_session_t *session);
wt_status_t wt_runtime_session_failure(const wt_runtime_session_t *session);

/* The application keys, once the handshake has them, so a caller can protect data traffic. WT_ERR_STATE
 * before then, which is the difference between "not yet" and "never". */
int wt_runtime_session_keys_ready(const wt_runtime_session_t *session);

void wt_runtime_session_clear(wt_runtime_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_RUNTIME_SESSION_H */
