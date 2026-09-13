/*
 * The QUIC connection runtime: one connection, its timer, and its socket.
 *
 * WHAT THIS LAYER DECIDES AND WHAT IT DOES NOT. It owns everything RFC 9000 asks a connection to
 * remember about packets: the four packet number spaces, the keys of each, the received sets and the
 * acknowledgements they owe, the sent-packet list with loss detection and probe timeouts, the
 * congestion controller, and the close paths. It does not own frames. A frame it does not have a rule
 * for -- CRYPTO, STREAM, the flow control limits, NEW_CONNECTION_ID, DATAGRAM -- is handed to a
 * handler the caller installs, which is where the TLS handshake, the stream layer and the WebTransport
 * session live. That seam is deliberate: it is what lets the packet layer be tested against a real
 * socket without a handshake, and it is what keeps the peer's frame types out of this file.
 *
 * THE EVENT LOOP IS THE CALLER'S, AND `now` IS A PARAMETER. There is no thread and no hidden timer:
 * `wt_quic_connection_receive` reads one datagram, `wt_quic_connection_flush` sends what is owed,
 * `wt_quic_connection_next_timeout` says how long the caller may wait, and `wt_quic_connection_on_timeout`
 * does what the deadline was for. A connection that is driven by a scheduler, a poll loop or a test
 * with a synthetic clock is the same connection, which is what makes the timer behavior testable at
 * all -- a wall clock inside this file would make every timing test a test of the machine's load.
 *
 * THE SOCKET IS BORROWED, NOT OWNED. The connection is given an open socket and an address and never
 * closes the descriptor: a caller that owns one socket and several connections (which is what a QUIC
 * server does, and what a test with two connections does) must not have the first connection to finish
 * close it. `wt_quic_connection_clear` zeroes the keys and nothing else.
 */

#ifndef WEBTRANSPORT_QUIC_CONNECTION_H
#define WEBTRANSPORT_QUIC_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/close.h"
#include "webtransport/quic/datagram.h"
#include "webtransport/quic/congestion.h"
#include "webtransport/quic/error.h"
#include "webtransport/quic/frame.h"
#include "webtransport/quic/loss.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/pn_space.h"
#include "webtransport/quic/protection.h"
#include "webtransport/quic/stream.h"
#include "webtransport/runtime/udp.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_quic_role {
  WT_QUIC_ROLE_CLIENT = 0,
  WT_QUIC_ROLE_SERVER = 1
} wt_quic_role_t;

/* The packet number spaces of RFC 9000 section 12.3. 0-RTT and 1-RTT share the Application space, so
 * there are three and not four. */
typedef enum wt_quic_space {
  WT_QUIC_SPACE_INITIAL = 0,
  WT_QUIC_SPACE_HANDSHAKE = 1,
  WT_QUIC_SPACE_APPLICATION = 2,
  WT_QUIC_SPACE_COUNT = 3
} wt_quic_space_t;

/* How many packets can be remembered as carrying retransmittable frames. The loss list itself holds
 * WT_QUIC_SENT_PACKETS_MAX, but a packet that carries nothing worth resending (an ACK, a PING) needs
 * no descriptor, so this is the number of CRYPTO or STREAM payloads in flight and not the number of
 * packets. A connection that reaches it refuses to send rather than sending something it cannot
 * retransmit, because a payload that is silently not retransmitted is a handshake or a stream that
 * stalls with nothing naming why. */
#define WT_QUIC_CONNECTION_FRAMES_MAX 16U

/* The wire bytes of the ranges of one ACK frame. Bounded because the alternative is a buffer sized by
 * a peer's packet count; a received set with more gaps than this sends what fits and the rest is
 * acknowledged by a later frame, which RFC 9000 section 13.2.4 allows. */
#define WT_QUIC_CONNECTION_ACK_RANGES_MAX 256U

/* What the peer's transport parameters say about what it will accept and what it allows. They are the
 * other half of every limit this endpoint enforces: a sender may not open more streams than the peer's
 * `initial_max_streams`, may not send more data than its `initial_max_data`, and may not send a
 * datagram larger than its `max_datagram_frame_size`. A parameter the peer did not send has the
 * default RFC 9000 section 18.2 gives it, which for the flow control limits is zero -- a peer that
 * says nothing grants nothing -- and for max_udp_payload_size is 65527. */
typedef struct wt_quic_peer_limits {
  uint64_t max_idle_timeout;      /* microseconds; 0 when the peer did not limit it */
  uint64_t max_udp_payload_size;  /* never below WT_QUIC_MIN_MAX_UDP_PAYLOAD_SIZE */
  uint64_t initial_max_data;
  uint64_t initial_max_stream_data_bidi_local;
  uint64_t initial_max_stream_data_bidi_remote;
  uint64_t initial_max_stream_data_uni;
  uint64_t initial_max_streams_bidi;
  uint64_t initial_max_streams_uni;
  uint64_t active_connection_id_limit;
  uint64_t max_datagram_frame_size; /* 0 when the peer does not support DATAGRAM at all */
  int set;                          /* whether a parameter list has been parsed at all */
} wt_quic_peer_limits_t;

/* A connection ID the PEER issued, with the stateless reset token that goes with it (RFC 9000 section
 * 19.15). Bounded by the `active_connection_id_limit` this endpoint advertised, because the peer may only
 * send as many as that and anything beyond it is the CONNECTION_ID_LIMIT_ERROR of section 5.1.1. */
typedef struct wt_quic_peer_connection_id {
  int in_use;
  uint64_t sequence;
  uint8_t id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t length;
  uint8_t reset_token[16];
} wt_quic_peer_connection_id_t;

#define WT_QUIC_PEER_CONNECTION_IDS_MAX 8U

typedef struct wt_quic_connection_config {
  wt_quic_role_t role;
  uint32_t version;
  /* The connection IDs. `local` is what this endpoint answers to and what it puts in the Source
   * Connection ID field; `peer` is what it sends to. Initial keys are bound to the *original*
   * destination connection ID, which is the caller's business and not this file's. */
  const uint8_t *local_connection_id;
  size_t local_connection_id_length;
  const uint8_t *peer_connection_id;
  size_t peer_connection_id_length;
  /* The AEAD every packet is protected with. RFC 9001 section 5.3 allows the *handshake* to negotiate
   * a different one per packet number space, which the keys carry, so this is the connection's default
   * and the one used when nothing else is set. */
  wt_aead_t aead;
  /* The two acknowledgement delays, which are different numbers and are confused easily. `max_ack_delay`
   * is the PEER's transport parameter: it is how long the peer may sit on an acknowledgement, so it is
   * what a round trip sample is allowed to subtract (RFC 9002 section 5.3). `local_max_ack_delay` is
   * this endpoint's own: how long IT may delay an acknowledgement before sending one (RFC 9000 section
   * 13.2.1), which is what arms the acknowledgement timer. */
  uint64_t max_ack_delay;
  uint64_t local_max_ack_delay;
  /* How many connection IDs THIS endpoint is willing to store from the peer, which is what it advertised
   * in its own `active_connection_id_limit`: RFC 9000 section 5.1.1 counts the handshake's ID among them,
   * and a peer that sends more is the CONNECTION_ID_LIMIT_ERROR of that section. Two -- the RFC's own
   * default -- is the smallest useful value and the one used when this is zero. */
  uint64_t local_active_connection_id_limit;
  /* The largest amount of stream data this endpoint will receive on ONE stream before raising the
   * limit: the receive-side counterpart of the peer's initial_max_stream_data_*, and zero -- which
   * grants nothing -- until a caller that knows what it can buffer sets it. */
  uint64_t local_max_stream_data;
  /* The longest this endpoint will let the connection sit idle before closing it silently (RFC 9000 section
   * 10.1), in MICROSECONDS, because it is compared against the same clock as `now`. The wire's
   * `max_idle_timeout` is in MILLISECONDS, and the conversion happens once, where the peer's parameters are
   * read (WT-145). Zero means no local limit. */
  uint64_t idle_timeout;
  /* The largest packet this path will carry. RFC 9000 section 14.1 requires every datagram to hold at
   * least WT_QUIC_MAX_PACKET, so a smaller value is refused rather than used. */
  size_t max_datagram_size;
} wt_quic_connection_config_t;

/* What a sent packet carried, so that a loss can be reported to whoever can send it again. This is
 * the caller's `tag` in the loss list's terms: the runtime keeps one per retransmittable packet and
 * hands it back when that packet is lost. `in_use` is how a slot is reused. */
typedef struct wt_quic_tx_frame {
  int in_use;
  wt_quic_space_t space;
  /* WHAT THE PACKET CARRIED, so the owner can send it again: a CRYPTO payload is bytes of the
   * handshake stream, and a STREAM payload is bytes of one stream. `stream_id` is meaningful only when
   * `is_crypto` is clear, and the tag's use is the same in both cases -- the connection hands the
   * descriptor back when the packet is declared lost, and the layer that keeps the bytes sends them
   * again. */
  int is_crypto;
  uint64_t stream_id;
  uint64_t offset;
  size_t length;
} wt_quic_tx_frame_t;

/* A frame this layer does not act on. The return value stops the walk of that packet: WT_OK continues,
 * anything else ends it and is returned by the receive call, which is how a handler reports a protocol
 * error. The frame is reused by the decoder between calls, so a handler that keeps one must copy it. */
typedef wt_status_t (*wt_quic_frame_handler_fn)(void *context, wt_quic_space_t space,
                                                const wt_quic_frame_t *frame);

/* A packet that was declared lost, and what it carried. Only packets with a descriptor are reported:
 * an acknowledgement has nothing to send again. */
typedef void (*wt_quic_frame_lost_fn)(void *context, const wt_quic_tx_frame_t *frame);

/* How many connection IDs this endpoint may have outstanding, beyond the one the handshake used: the
 * peer's `active_connection_id_limit`, less the initial one, because RFC 9000 section 5.1.1 counts that
 * ID among what the peer will store. */
#define WT_QUIC_CONNECTION_IDS_MAX 8U

typedef struct wt_quic_issued_connection_id {
  int in_use;
  uint64_t sequence;
  uint8_t id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t length;
  uint8_t reset_token[16];
} wt_quic_issued_connection_id_t;

typedef struct wt_quic_connection {
  wt_quic_connection_config_t config;

  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  int has_peer;

  /* The connection IDs, copied out of the configuration so that the caller's buffers may go away. */
  uint8_t local_connection_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t local_connection_id_length;
  uint8_t peer_connection_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t peer_connection_id_length;

  /* One key set per space and direction. A direction that has not been installed -- the Handshake
   * keys before the handshake produces them -- means a packet for that space cannot be read or sent,
   * which is reported rather than guessed. */
  wt_quic_packet_keys_t keys_in[WT_QUIC_SPACE_COUNT];
  wt_quic_packet_keys_t keys_out[WT_QUIC_SPACE_COUNT];
  int has_keys_in[WT_QUIC_SPACE_COUNT];
  int has_keys_out[WT_QUIC_SPACE_COUNT];

  wt_quic_pn_space_t spaces[WT_QUIC_SPACE_COUNT];
  wt_quic_loss_t loss;
  wt_quic_congestion_t congestion;
  wt_quic_close_state_t close;
  /* The peer's limits, parsed from the transport parameters its handshake carried. */
  wt_quic_peer_limits_t peer_limits;
  /* The connection-level limit this endpoint grants the peer, and whether it has been seeded. */
  uint64_t local_max_data;
  int local_max_data_set;
  /* The connection IDs this endpoint has issued, bounded: a NEW_CONNECTION_ID is peer-visible state and
   * an endpoint that issued them without a bound would be growing on its own instructions. */
  wt_quic_issued_connection_id_t issued_ids[WT_QUIC_CONNECTION_IDS_MAX];
  size_t issued_count;
  /* The sequence number the next issued ID will carry. RFC 9000 section 5.1.1 gives the connection ID the
   * handshake used sequence 0, so the first ID a peer is TOLD about is sequence 1: numbering the spares
   * from zero would announce a second ID under a sequence the handshake's ID already owns, and a
   * RETIRE_CONNECTION_ID naming that sequence would be ambiguous. */
  uint64_t next_issued_sequence;
  /* And the ones the peer has issued to this endpoint. */
  wt_quic_peer_connection_id_t peer_ids[WT_QUIC_PEER_CONNECTION_IDS_MAX];
  size_t peer_id_count;
  /* The streams this connection has, bounded by the table. */
  wt_quic_stream_table_t streams;
  /* The CONNECTION-level flow control, both directions: what this endpoint has granted and received,
   * and what the peer granted. The per-stream limits live on the streams; these are the sum the RFC
   * checks first (RFC 9000 section 4.1). */
  wt_quic_flow_t flow;
  uint64_t local_max_streams[2]; /* indexed by wt_quic_stream_direction_t */
  int local_max_streams_set[2];
  /* The datagrams that have arrived and not been read, bounded and with the newest discarded when it
   * is full (RFC 9221's frames are unreliable, so dropping one is not an error). */
  wt_quic_datagram_queue_t datagrams;

  wt_quic_tx_frame_t frames[WT_QUIC_CONNECTION_FRAMES_MAX];

  wt_quic_frame_handler_fn handler;
  void *handler_context;
  /* Set by a frame handler that is about to refuse a frame, so that the CONNECTION_CLOSE the connection
   * then sends names the handler's error code rather than a generic one. It matters most for the TLS
   * handshake: RFC 9000 section 20.1 puts a failed handshake in CRYPTO_ERROR with the alert in its low
   * byte, and a peer that reads INTERNAL_ERROR where a CRYPTO_ERROR belongs cannot tell a refused
   * certificate from a broken implementation. The handler sets `close_code` (and, if it knows it, the
   * frame type) before returning a failure; the connection clears the hint after using it. */
  uint64_t close_code;
  uint64_t close_frame_type;
  int close_code_set;
  /* Why THIS endpoint closed, as the status of the handler that refused the frame. It is kept after the close
   * because `close_code` above is a HINT that is cleared once it has been used, so a caller reading it to ask
   * "what did we actually send" reads nothing -- which is how a tool reported a successful session after the
   * connection had been closed with INTERNAL_ERROR (WT-144). */
  wt_status_t close_cause;
  wt_quic_frame_lost_fn lost_handler;
  void *lost_context;

  /* When the last packet arrived or was sent, for the idle timeout, and when the packet that was
   * acknowledged most recently arrived in each space, which is the delay an acknowledgement reports. */
  uint64_t last_activity;
  uint64_t received_at[WT_QUIC_SPACE_COUNT];

  uint64_t packets_sent;
  uint64_t packets_received;
  uint64_t bytes_sent;
  uint64_t bytes_received;
  /* Every frame the walk visited, how many of them were STREAM frames, and how many reached the caller's
   * handler. They are diagnostics rather than protocol state, and they exist because a session whose
   * packets arrive and whose handler is never called has exactly one question to ask -- did the walk see
   * the frame? -- and no way to ask it from outside. */
  uint64_t frames_walked;
  uint64_t stream_frames_seen;
  uint64_t frames_delivered;
  /* Whether the handshake is confirmed, which RFC 9002 section 5.3 requires before an acknowledgement
   * delay is subtracted from a round trip sample. */
  int handshake_confirmed;
  /* Packets DECLARED lost, by packet-number space, and how many of those could not name a retransmission
   * descriptor. Two counters, because "the loss was never declared" and "the loss had nothing to name" are the
   * two ways a lost frame goes unreported -- and reading the code had already failed to tell them apart (WT-135). */
  uint64_t packets_declared_lost[WT_QUIC_SPACE_COUNT];
  uint64_t lost_without_descriptor;
  /* Probe timeouts that fired, by space, and how many of them had an outstanding frame to report. A probe is not
   * a loss, so the counters above cannot say whether the timer ran at all -- and "no probe" and "probe with
   * nothing to report" are different defects (WT-135). */
  uint64_t probes_sent[WT_QUIC_SPACE_COUNT];
  uint64_t probes_with_data;
  /* Packets SENT, by space. "Did we send a Handshake-level packet at all" is the difference between a client that
   * never finished its handshake and one whose Finished the peer cannot read, and the peer's log looks identical
   * either way (WT-135). */
  uint64_t packets_sent_by_space[WT_QUIC_SPACE_COUNT];
  /* ACK frames SENT, by space, and the largest packet number each named. "Is an acknowledgement going out, and
   * does it name a packet the peer actually sent" is what the peer's "Scheduled CRYPTO data for retransmission"
   * is asking from its side (WT-135). */
  uint64_t acks_sent[WT_QUIC_SPACE_COUNT];
  uint64_t ack_largest[WT_QUIC_SPACE_COUNT];

  /* Whether a CONNECTION_CLOSE frame has been sent, so that closing twice does not send two. A close
   * that is silent -- the idle timeout, RFC 9000 section 10.1 -- sets this without sending, which is
   * how "do not send" and "have not sent yet" are told apart. */
  int close_sent;

  /* Whether a CONNECTION_CLOSE FRAME actually went to the peer, which `close_sent` above does not say: the idle
   * timeout closes silently (RFC 9000 section 10.1) and sets `close_sent` too, because it means "send nothing
   * further" rather than "one was sent". The difference is the whole question a tool asks -- did the peer get
   * told the connection is over, or did this endpoint simply give up? -- and answering it from `close` alone is
   * how a silent idle timeout would read as a close this endpoint announced (WT-144, WT-145). */
  int close_frame_sent;

  /* The close the peer sent. It is separate from `close` above, which is this endpoint's own intent:
   * the peer's close ends the connection without this endpoint sending anything, and a caller that
   * wanted to know why needs the peer's code rather than its own. The reason phrase is copied, because
   * the frame's bytes are the decrypted packet buffer and do not outlive the datagram. */
  int peer_closed;
  wt_quic_close_kind_t peer_close_kind;
  uint64_t peer_error_code;
  uint64_t peer_frame_type;
  uint8_t peer_reason[64];
  size_t peer_reason_length;

  /* Packets dropped before they were read: a destination connection ID that is not this endpoint's,
   * or a failure that RFC 9001 section 5.3 says to discard for rather than to act on. */
  uint64_t packets_discarded;
} wt_quic_connection_t;

/* Set the connection up. The configuration is copied; the connection IDs it points at are copied too,
 * so a caller may let its own buffer go. Refuses a null connection or configuration, a connection ID
 * longer than twenty bytes, a datagram size below WT_QUIC_MAX_PACKET, and an AEAD of none. */
wt_status_t wt_quic_connection_init(wt_quic_connection_t *connection,
                                    const wt_quic_connection_config_t *config);

/* Borrow `socket` and send to `peer`. A null `peer` is allowed only for a server that learns its
 * peer's address from the first packet, which is what RFC 9000 section 7.2's server does. */
wt_status_t wt_quic_connection_attach(wt_quic_connection_t *connection,
                                      const wt_udp_socket_t *socket,
                                      const wt_udp_address_t *peer);

/* Install one direction's keys for a space. The keys are copied and zeroed by
 * `wt_quic_connection_clear`. */
wt_status_t wt_quic_connection_set_keys(wt_quic_connection_t *connection, wt_quic_space_t space,
                                        int inbound, const wt_quic_packet_keys_t *keys);

/* Parse the peer's transport parameters, which the TLS handshake carried, and keep the limits they
 * state. The idle timeout this connection uses becomes the smaller of its own and the peer's, because
 * RFC 9000 section 10.1 makes the effective idle timeout the minimum of the two -- a connection that
 * enforced only its own would stay open after the peer had forgotten it, and one that enforced only the
 * peer's would outlive its own configuration.
 *
 * WT_ERR_PROTOCOL when the list breaks RFC 9000 section 18.2's rules (with the offender available from
 * the codec), WT_ERR_TRUNCATED when a parameter's length runs past the end of the extension. */
wt_status_t wt_quic_connection_set_peer_parameters(wt_quic_connection_t *connection,
                                                   const uint8_t *data, size_t length);

/* The peer's limits, and whether any have been parsed. A caller that sends streams or datagrams reads
 * them: `set` is 0 before the handshake has produced them, and a limit the peer did not send is zero,
 * which is the RFC's default and means "none granted". */
const wt_quic_peer_limits_t *wt_quic_connection_peer_limits(const wt_quic_connection_t *connection);

/* Send one DATAGRAM frame (RFC 9221). The payload is bounded by BOTH the peer's
 * `max_datagram_frame_size` -- zero means it does not accept datagrams at all, which is
 * WT_ERR_UNSUPPORTED rather than a limit -- and what the path will carry, and the smaller of the two is
 * what is enforced. A datagram is not retransmitted and carries no retransmission descriptor: that is
 * what makes it unreliable, and a caller that needs the bytes to arrive uses a stream.
 *
 * WT_ERR_LIMIT when the payload is larger than either bound, WT_ERR_STATE before the peer's parameters
 * have been parsed (nothing is known about what it accepts), WT_ERR_AGAIN when the congestion window has
 * no room. */
wt_status_t wt_quic_connection_send_datagram(wt_quic_connection_t *connection, const uint8_t *data,
                                             size_t length, uint64_t now);

/* Open a stream this endpoint initiates, and report its number.
 *
 * The number is derived from the counts the table keeps -- a client's bidirectional streams are 0, 4, 8
 * and so on, its unidirectional ones 2, 6, 10 (RFC 9000 section 2.1) -- so a number is never reused and
 * never invented by the caller. The new stream starts with the flow control this endpoint's
 * configuration grants: its own `local_max_stream_data` for receiving and the peer's
 * `initial_max_stream_data_*` for sending, which is where the two directions' different limits come
 * from.
 *
 * WT_ERR_STATE before the peer's transport parameters have been parsed (nothing is known about what it
 * will accept), WT_ERR_LIMIT when the peer's `initial_max_streams_*` does not allow one more, and
 * WT_ERR_LIMIT when the table is full -- the caller tells those apart by reading the counts. */
wt_status_t wt_quic_connection_open_stream(wt_quic_connection_t *connection, int bidirectional,
                                           uint64_t *out_stream_id);

/* The connection's streams, and the table's own answers. */
wt_quic_stream_table_t *wt_quic_connection_streams(wt_quic_connection_t *connection);
wt_quic_stream_t *wt_quic_connection_stream(wt_quic_connection_t *connection, uint64_t stream_id);

/* Cancel a stream this endpoint is sending on: RFC 9000 section 19.4's RESET_STREAM ends the send half
 * with an application error code and the final size the peer needs to tell a truncated stream from a
 * complete one. The stream's state moves to Reset Sent, which is what stops anything further being sent
 * on it.
 *
 * WT_ERR_STATE before the peer's parameters are known or for a stream that is not this endpoint's to send
 * on -- a peer's unidirectional stream, or a number that was never opened -- WT_ERR_STATE for a send half
 * that has already finished, and WT_ERR_AGAIN when the congestion window has no room. */
wt_status_t wt_quic_connection_reset_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                                            uint64_t error_code, uint64_t now);

/* Ask the peer to stop sending on a stream: RFC 9000 section 19.5's STOP_SENDING, with the application
 * error code the peer will see in the RESET_STREAM it is expected to answer with (section 3.5).
 *
 * It is the other half of cancellation: a RESET_STREAM cancels what THIS endpoint is sending, and a
 * STOP_SENDING asks the peer to stop what it is sending. The stream must exist and this endpoint must be
 * receiving on it, and one may only be sent once -- a second is the STREAM_STATE_ERROR of section 19.5
 * rather than a duplicate to be ignored. */
wt_status_t wt_quic_connection_stop_sending(wt_quic_connection_t *connection, uint64_t stream_id,
                                            uint64_t error_code, uint64_t now);

/* Send one STREAM frame (RFC 9000 section 19.8) carrying `length` bytes of `stream_id` at `offset`,
 * with FIN when this is the end of the stream.
 *
 * WHAT THIS IS AND IS NOT. It is the wire half of sending on a stream: it checks that the stream is one
 * this endpoint may open at all against the peer's `initial_max_streams_bidi`/`_uni`, encodes the frame
 * and sends it. It is NOT the stream layer: nothing here remembers the bytes, so a STREAM frame is not
 * retransmitted (the caller that keeps the data must send it again), and nothing counts the flow control
 * credit spent -- `wt_quic_connection_peer_limits` is what a stream layer reads to do that. It exists
 * because the send path and the wire format are worth having and testing on their own, and because the
 * stream layer's first part is exactly this plus the state that remembers.
 *
 * WT_ERR_LIMIT when the stream number is beyond what the peer granted, WT_ERR_STATE before its parameters
 * have been parsed, WT_ERR_INVALID_ARGUMENT for a null payload with a length, WT_ERR_AGAIN when the
 * congestion window has no room. */
wt_status_t wt_quic_connection_send_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                                           uint64_t offset, const uint8_t *data, size_t length,
                                           int fin, uint64_t now);

/* Issue a connection ID this endpoint is willing to answer to, and tell the peer with a NEW_CONNECTION_ID
 * (RFC 9000 section 19.15). `reset_token` is the stateless reset token that goes with it: it must be
 * unguessable and it is the caller's to derive from a secret this layer does not hold (RFC 9000 section
 * 10.3), so it is taken rather than invented.
 *
 * Refuses a connection ID of a length other than this endpoint's own, because a short header does not
 * carry that length and an ID of another length could never be received here; a connection ID longer than
 * twenty bytes or shorter than one (section 17.2); a sequence number
 * already used -- RFC 9000 section 19.15 makes a repeat a PROTOCOL_VIOLATION, and this layer reports it as
 * a caller error before anything is sent -- a null reset token, and one more ID than the peer's
 * `active_connection_id_limit` allows, because a peer that cannot store it is a peer that will close the
 * connection. WT_ERR_LIMIT when this endpoint's own bounded table of issued IDs is full. */
wt_status_t wt_quic_connection_issue_connection_id(wt_quic_connection_t *connection,
                                                   const uint8_t *id, size_t length,
                                                   const uint8_t reset_token[16], uint64_t now);

/* The connection ID issued with this sequence number, or NULL. */
const wt_quic_issued_connection_id_t *wt_quic_connection_issued_id(
    const wt_quic_connection_t *connection, uint64_t sequence);

/* Send one MAX_DATA frame (RFC 9000 section 19.9): the connection-level flow control limit this
 * endpoint grants the peer, counted in bytes of stream data received in total.
 *
 * This is the limit this endpoint ADVERTISES, which is the other direction from `peer_limits`: what the
 * peer granted this endpoint is parsed from its transport parameters, and what this endpoint grants the
 * peer needs to be raised as the application reads. RFC 9000 section 4.1 makes a limit that only ever
 * decreases a protocol error, so a caller must not lower one; this function refuses a limit below the
 * last one it sent for exactly that reason, and the caller that owns the receive accounting is the one
 * that knows when there is more room.
 *
 * The initial value is the one this endpoint sent in its own `initial_max_data` transport parameter,
 * which this layer does not send, so `wt_quic_connection_set_max_data` seeds it: a caller that parses its
 * own parameters (or simply knows what it advertised) sets it there and this function then only ever
 * raises it. WT_ERR_STATE before that seed, WT_ERR_LIMIT for a limit that does not advance. */
wt_status_t wt_quic_connection_set_max_data(wt_quic_connection_t *connection, uint64_t maximum);
wt_status_t wt_quic_connection_send_max_data(wt_quic_connection_t *connection, uint64_t maximum,
                                             uint64_t now);
uint64_t wt_quic_connection_max_data(const wt_quic_connection_t *connection);

/* The stream-count limits this endpoint grants, the same shape as the connection-level one above and for
 * the same reason: RFC 9000 section 4.6 makes a MAX_STREAMS that decreases a protocol error, because the
 * peer has already been told it may open that many. The two directions have separate counts, since a
 * bidirectional stream costs the peer one of its own and one of ours while a unidirectional one costs
 * only ours. `direction` is the direction of the streams being granted, which is what the frame carries. */
wt_status_t wt_quic_connection_set_max_streams(wt_quic_connection_t *connection,
                                               wt_quic_stream_direction_t direction,
                                               uint64_t maximum);
wt_status_t wt_quic_connection_send_max_streams(wt_quic_connection_t *connection,
                                                wt_quic_stream_direction_t direction,
                                                uint64_t maximum, uint64_t now);
uint64_t wt_quic_connection_max_streams(const wt_quic_connection_t *connection,
                                        wt_quic_stream_direction_t direction);

/* The largest DATAGRAM payload this connection may send right now: the smaller of the peer's frame
 * limit and what the path carries, with the frame's own length field accounted for. Zero when the peer
 * does not accept datagrams. */
uint64_t wt_quic_connection_max_datagram_payload(const wt_quic_connection_t *connection);

/* A received DATAGRAM frame, for a caller's frame handler to hand to the connection: this is the
 * receive half of the same API, and it is a function rather than something this layer does by itself so
 * that a frame handler composed of several consumers can decide what to do with it. A datagram the queue
 * cannot hold is discarded and counted, never refused, because a datagram is not guaranteed to arrive. */
wt_status_t wt_quic_connection_on_datagram(wt_quic_connection_t *connection, const uint8_t *data,
                                           size_t length, uint64_t now);

/* Take the oldest datagram that arrived. WT_ERR_AGAIN when there is none. */
wt_status_t wt_quic_connection_receive_datagram(wt_quic_connection_t *connection, uint8_t *out,
                                                size_t capacity, size_t *out_length,
                                                uint64_t *out_received_at);

/* Discard one space's keys, in both directions. RFC 9001 section 4.9 makes this a MUST, not a
 * tidy-up: the Initial keys are derived from a connection ID both ends can see, so an endpoint that
 * keeps them stays readable to anyone who saw the first packet, and the Handshake keys are no better
 * once the handshake is confirmed. The connection does it by itself where the RFC says when -- the
 * Initial keys go when a Handshake packet is first received or sent, the Handshake keys when the
 * handshake is confirmed -- and this is exposed because a caller that ends a connection early has to be
 * able to do it too. Idempotent, and a space that never had keys is not an error. */
wt_status_t wt_quic_connection_discard_keys(wt_quic_connection_t *connection, wt_quic_space_t space);

/* Install the frame and loss handlers. Both are optional; without the first, frames this layer does
 * not act on are ignored -- which is correct for a connection whose owner has nothing to do with them
 * yet, and wrong for a connection that needs them. */
void wt_quic_connection_set_handlers(wt_quic_connection_t *connection,
                                     wt_quic_frame_handler_fn handler, void *handler_context,
                                     wt_quic_frame_lost_fn lost_handler, void *lost_context);

/* Send one CRYPTO payload in one packet. The bytes are not copied: the descriptor records where they
 * are in the handshake stream, and a loss is reported to the lost handler so that the owner can send
 * them again from the buffer it owns. Returns WT_ERR_AGAIN when the congestion window or the loss
 * list has no room, which is the caller's signal to try later; WT_ERR_LIMIT when every retransmission
 * slot is taken. */
wt_status_t wt_quic_connection_send_crypto(wt_quic_connection_t *connection, wt_quic_space_t space,
                                           uint64_t offset, const uint8_t *data, size_t length,
                                           uint64_t now);

/* Send one frame by itself, in one packet, with the keys of that space.
 *
 * This is the general path for the frames this layer does not produce -- HANDSHAKE_DONE, the flow
 * control limits, the stream frames -- and it takes a frame the frame codec has already validated.
 * `ack_eliciting` is the caller's to state because it follows from the frame's type (RFC 9000 section
 * 13.2.1): PADDING, ACK and CONNECTION_CLOSE do not ask for an acknowledgement and everything else
 * does. It refuses, rather than silently succeeding, when the congestion window, the loss list or a
 * retransmission slot has no room. */
wt_status_t wt_quic_connection_send_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame, int ack_eliciting,
                                          uint64_t now);

/* Send an acknowledgement if one is owed in this space, and a probe (an ack-eliciting PING) if one is
 * owed because a probe timeout fired. Returns WT_OK whether or not anything was sent; the count of
 * packets sent is the caller's way to tell. */
wt_status_t wt_quic_connection_flush(wt_quic_connection_t *connection, uint64_t now);

/* Read and process one datagram. WT_ERR_AGAIN when none is waiting, which is not a failure.
 *
 * A packet that fails authentication ends the datagram: RFC 9001 section 5.3 discards it, and the
 * packets coalesced after it cannot be found reliably once one has been skipped. A protocol error in a
 * frame closes the connection and is reported. */
wt_status_t wt_quic_connection_receive(wt_quic_connection_t *connection, uint64_t now);

/* How long the caller may wait before calling `wt_quic_connection_on_timeout`, and WT_ERR_STATE when
 * no timer is armed -- which is not the same as a zero delay: a connection with nothing in flight
 * waits for the application, indefinitely. */
wt_status_t wt_quic_connection_next_timeout(wt_quic_connection_t *connection, uint64_t now,
                                           uint64_t *out_micros);

/* Do what the deadline was armed for: declare packets lost, send a probe, or end an idle or draining
 * period. */
wt_status_t wt_quic_connection_on_timeout(wt_quic_connection_t *connection, uint64_t now);

/* Close, sending a CONNECTION_CLOSE frame if one has not been sent. RFC 9000 section 10.2: the intent
 * to close is a frame, so this sends it and then waits out the draining period. A reason phrase is a
 * view and must outlive the call, which is why it is passed and not stored. */
wt_status_t wt_quic_connection_close(wt_quic_connection_t *connection, uint64_t error_code,
                                     uint64_t frame_type, const uint8_t *reason, size_t reason_length,
                                     uint64_t now);

/* Whether the peer closed, so that nothing but PADDING and the close's own frames is processed. */
int wt_quic_connection_is_closed(const wt_quic_connection_t *connection);

/* The close THIS endpoint sent: its kind, error code, frame type and reason phrase, or a state whose kind is
 * `WT_QUIC_CLOSE_NONE` when it has sent none. It is the record of what the peer was told, which is a different
 * question from `close_code`'s -- that is the hint a refusing handler leaves, and the connection clears it once
 * it has been used (WT-144). The state is owned by the connection and the reason phrase is a view into the
 * caller's bytes, so it lives as long as whatever passed them to `wt_quic_connection_close`. */
const wt_quic_close_state_t *wt_quic_connection_close_state(const wt_quic_connection_t *connection);

/* The status of the handler whose refusal closed this connection, or WT_OK when no handler refused -- a close
 * this endpoint chose deliberately, or one the peer sent, has no cause here. A tool asks because a session that
 * ended this way did NOT end well, whatever the exchange counters say. */
wt_status_t wt_quic_connection_close_cause(const wt_quic_connection_t *connection);

/* Whether a CONNECTION_CLOSE frame was actually SENT to the peer. A close this endpoint decided on but never
 * announced -- the idle timeout, RFC 9000 section 10.1 -- is not one the peer was told about, so a caller must
 * ask this and not infer it from `wt_quic_connection_close_state`: the state is set either way (WT-144). */
int wt_quic_connection_close_was_sent(const wt_quic_connection_t *connection);

/* Whether the draining period has passed, after which the connection is gone and its state may be
 * released. */
int wt_quic_connection_is_drained(const wt_quic_connection_t *connection, uint64_t now);

/* Zero the keys and forget the peer. Does not close the socket, which the connection never owned. */
void wt_quic_connection_clear(wt_quic_connection_t *connection);

/* The name of a space, for diagnostics: "initial", "handshake", "application". Never NULL. */
const char *wt_quic_space_name(wt_quic_space_t space);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_CONNECTION_H */
