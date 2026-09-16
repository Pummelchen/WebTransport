/* One-sided session loops for the client and server tools (Phase 9): the shared machinery.
 *
 * `wt_loop_run_client` and `wt_loop_run_server` are one side of a real socket pair each, and this
 * file is everything they have in common: the sink the driver reports a session's frames, streams
 * and datagrams through, the section it assembles, the buffering section 4.6's early streams and
 * datagrams go into, the transport parameters and connection configuration, the close/wait status
 * helpers, the report, the pump, and the one message sender. The two loops themselves are
 * `session_loop_client.c` and `session_loop_server.c`; "session_loop_internal.h" is where they see
 * this file's declarations. */

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

static wt_status_t side_on_frame_payload(void *context, uint64_t stream_id, uint64_t type,
                                         const uint8_t *payload, size_t length, int last);
static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin);
static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length);

const char *wt_loop_status_name(wt_status_t status) { return wt_status_name(status); }

void init_side(loop_side_t *side, wt_http3_role_t role) {
  memset(side, 0, sizeof(*side));
  wt_http3_endpoint_init(&side->endpoint, role);
  wt_http3_driver_init(&side->driver, &side->endpoint);
  wt_capsule_stream_init(&side->capsules);
  side->sink.context = side;
  side->sink.on_frame_payload = side_on_frame_payload;
  side->sink.on_stream_data = side_on_stream_data;
  side->sink.on_datagram = side_on_datagram;
}

/* The session's streams, ended when the session is (draft-16 section 6).
 *
 * The capsule stream -- shared with the conformance tool -- owns the session object and knows when it closes; the
 * DRIVER owns the data streams; this is where the two meet, one call, and the driver's own flag makes it
 * idempotent so every close path can call it without bookkeeping. Nothing is sent into a session that is over
 * afterwards, which is the section's other MUST. */
static void end_session_streams_if_closed(loop_side_t *side) {
  size_t ended = 0U;

  if (side == NULL || side->connection == NULL) return;
  if (wt_http3_driver_session_ended(&side->driver) != 0) return;
  if (side->capsules.session.state != WT_WEBTRANSPORT_SESSION_CLOSED) return;
  (void)wt_http3_driver_end_session_streams(&side->driver, side->now_for_close, &ended);
}

static wt_status_t side_on_frame_payload(void *context, uint64_t stream_id, uint64_t type,
                                         const uint8_t *payload, size_t length, int last) {
  loop_side_t *side = context;
  /* A DIAGNOSTIC, gated by the same file the request's field section goes to: what this stream carries AFTER the
   * response. Draft-16 puts the session's capsules on the CONNECT stream, and a third-party peer's flow-control
   * capsule read as an HTTP/3 frame is a frame whose length runs past the end of the stream (WT-156). */
  {
    const char *log_path = getenv("WT_HTTP3_SECTION_LOG");
    if (log_path != NULL) {
      FILE *log = fopen(log_path, "a");
      if (log != NULL) {
        size_t index;
        fprintf(log, "frame stream=%llu type=%llu length=%llu last=%d bytes=",
                (unsigned long long)stream_id, (unsigned long long)type, (unsigned long long)length, last);
        for (index = 0U; index < length && index < 64U; index++) {
          fprintf(log, "%02x", payload[index]);
        }
        fprintf(log, "\n");
        (void)fclose(log);
      }
    }
  }
  if (type == WT_HTTP3_FRAME_HEADERS && stream_id == side->request_stream_id) {
    if (length > sizeof(side->section) - side->section_length) {
      /* The section is larger than this tool's scratch, and the first version dropped it in silence -- no copy, no
       * `section_complete`, no error -- so the client loop ran to its deadline and reported `"status":"timeout"`.
       * A bound this tool imposed read as the peer never answering, which is the failure mode the capsule path
       * beside it already refuses to have (`capsule_stream.c` sets a limit outcome for the same reason). The
       * status is WT_ERR_LIMIT with no error code: the peer did nothing wrong. */
      side->section_overflow = 1;
      return WT_ERR_LIMIT;
    }
    if (length > 0U) memcpy(side->section + side->section_length, payload, length);
    side->section_length += length;
    if (last != 0) side->section_complete = 1;
    return WT_OK;
  }
  return WT_OK;
}

static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin) {
  loop_side_t *side = context;
  wt_status_t status;

  /* The CONNECT stream is the session's, not a data stream's: its bytes after the one HEADERS frame are capsules
   * (draft-16 section 5), and the driver routes them here rather than framing them (WT-164). */
  if (stream_id == side->request_stream_id) {
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    status = wt_capsule_stream_on_bytes(&side->capsules, data, length, fin, wt_capsule_stream_apply_flow,
                                        &side->capsules, &error);
    /* A close capsule in either direction, or the CONNECT stream ending, is the session's end: section 6's reset
     * of its streams follows here, and it is idempotent, so every path below can reach it. */
    end_session_streams_if_closed(side);
    if (status != WT_OK) {
      /* A refusal the peer has to be told about, in whichever error space it belongs to. The status is still
       * returned, because a hint is not a close: the QUIC layer closes when the handler that refused says so. */
      side->capsule_error = (uint64_t)error;
      if (wt_capsule_stream_refuse(&side->capsules, side->transport, side->request_stream_id, side->connection,
                                   side->now_for_close, error) == WT_CAPSULE_REFUSAL_SESSION) {
        /* The session is closed and the peer has been told in the capsule itself: the connection stays up, so this
         * failure must NOT reach the transport (section 5.1, WT-165). */
        return WT_OK;
      }
    }
    return status;
  }
  /* Draft-16 section 4.6's STREAM half (WT-180). A data stream can arrive before the session it names is known --
   * a client sends its CONNECT, its streams and its datagrams in one flight -- and the draft says to BUFFER it
   * until it can be associated rather than refuse it. The session the stream names is in its prefix, which the
   * driver parsed and can be asked for; until the ID is known here, the stream is parked by the section's own
   * buffer. Over the buffer's bound the section names the answer: "a stream MUST be closed by sending a
   * RESET_STREAM and/or STOP_SENDING with the WT_BUFFERED_STREAM_REJECTED error code", which the driver sends. */
  if (side->session_known == 0) {
    uint64_t named = 0U;
    if (wt_http3_driver_data_stream_session_id(&side->driver, stream_id, &named) == WT_OK &&
        wt_webtransport_buffered_park_stream(&side->buffered, stream_id, named,
                                             wt_quic_stream_id_is_bidirectional(stream_id) == 0 ? 1 : 0,
                                             data, length) == WT_OK) {
      return WT_OK;
    }
    if (side->connection != NULL) {
      (void)wt_http3_driver_reject_data_stream(&side->driver, stream_id,
                                               WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED,
                                               side->now_for_close);
    }
    return WT_OK;
  }
  if (side->data_bytes + length <= sizeof(side->data)) {
    if (length > 0U) memcpy(side->data + side->data_bytes, data, length);
    side->data_bytes += length;
  }
  side->data_was_datagram = 0;
  return WT_OK;
}

/* Take a datagram's payload as this session's message. */
static void side_take_datagram(loop_side_t *side, const uint8_t *payload, size_t payload_length) {
  if (side->data_bytes + payload_length <= sizeof(side->data)) {
    if (payload_length > 0U) memcpy(side->data + side->data_bytes, payload, payload_length);
    side->data_bytes += payload_length;
  }
  side->data_was_datagram = 1;
}

static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length) {
  loop_side_t *side = context;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  uint64_t quarter = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* A datagram arrives with the draft's own framing: the quarter stream ID names the SESSION, and the payload is
   * what the caller asked for. The ID is checked -- the comment here used to claim it was while the code only
   * parsed the framing -- because the library's own session object checks it and `docs/PUBLIC-API.md` states the
   * rule: "a stream or datagram naming another session is refused with HTTP/3's identifier error, never delivered
   * to the wrong session and never dropped silently" (WT-179). */
  if (wt_webtransport_datagram_parse(data, length, &quarter, &payload, &payload_length, &error) != WT_OK) {
    return WT_OK;
  }

  if (side->session_known == 0) {
    /* Draft-16 section 4.6: a datagram can arrive before the session it belongs to is known -- the client sends
     * its CONNECT, its data streams and its datagrams in one flight -- and such a datagram is PARKED rather than
     * refused or delivered, because until the ID is known there is no way to tell "mine, early" from "not mine".
     * The bound is the section's MUST, and the buffer owns it: a datagram over it is dropped, not refused. */
    (void)wt_webtransport_buffered_park_datagram(&side->buffered, quarter, payload, payload_length);
    return WT_OK;
  }

  if (quarter != wt_webtransport_quarter_stream_id(side->request_stream_id)) {
    wt_quic_connection_refuse_application(side->connection, (uint64_t)WT_HTTP3_ID_ERROR, 0U);
    return WT_ERR_STATE;
  }
  side_take_datagram(side, payload, payload_length);
  return WT_OK;
}

/* The session's ID is known now: drain what was parked while it was not.
 *
 * This is the other half of section 4.6's buffering rule, for BOTH halves of it. A parked stream or datagram that
 * names THIS session is delivered -- the stream's bytes as this session's message, the datagram's payload the
 * same way -- and one that names another is dropped rather than refused, because it was never an error at the
 * time it arrived: the reference point did not exist yet. A stream or datagram that arrives AFTER this point and
 * names another session is the error the section 4.2 rule covers, and the paths above refuse it. */
static wt_status_t side_take_parked_stream(void *context, uint64_t stream_id, int unidirectional,
                                           const uint8_t *data, size_t length) {
  loop_side_t *side = context;
  (void)stream_id;
  (void)unidirectional;
  if (side->data_bytes + length <= sizeof(side->data)) {
    if (length > 0U) memcpy(side->data + side->data_bytes, data, length);
    side->data_bytes += length;
  }
  side->data_was_datagram = 0;
  return WT_OK;
}

static wt_status_t side_take_parked_datagram(void *context, uint64_t quarter_stream_id,
                                             const uint8_t *payload, size_t length) {
  loop_side_t *side = context;
  (void)quarter_stream_id;
  side_take_datagram(side, payload, length);
  return WT_OK;
}

void side_session_known(loop_side_t *side) {
  size_t delivered = 0U;
  size_t dropped = 0U;

  if (side->session_known != 0) return;
  side->session_known = 1;
  /* The streams first, in the order they arrived: a message's bytes are the session's, and the order a session
   * sees its messages in is the order they arrived in. */
  (void)wt_webtransport_buffered_drain_streams(&side->buffered, side->request_stream_id,
                                               side_take_parked_stream, side, &delivered, &dropped);
  (void)wt_webtransport_buffered_drain_datagrams(
      &side->buffered, wt_webtransport_quarter_stream_id(side->request_stream_id),
      side_take_parked_datagram, side, &delivered, &dropped);
}

wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  loop_side_t *side = context;
  wt_status_t status;

  side->frames_seen++;
  /* The DRIVER states its own refusals to the connection it is bound to -- an HTTP/3 error becomes an application
   * close carrying the HTTP/3 code (RFC 9114 section 8) -- so this boundary has nothing to translate. It was
   * translated here first, and a translation in each caller is one a caller will forget (WT-159). */
  status = wt_http3_driver_on_quic_frame(&side->driver, space, frame, &side->sink, 16384U);
  return status;
}

/* The endpoint's transport parameters, built by the LIBRARY: the mandatory connection-ID parameters live in
 * `wt_quic_transport_parameters_build` so that this file cannot forget one. It did forget one -- the parameter
 * that says which Source Connection ID these packets carry -- and only a third-party peer ever said so (WT-141).
 *
 * `source` is the ID these packets carry; `original_destination` is the one the CLIENT put in its first Initial,
 * which only a server sends (RFC 9000 section 7.3) and which the client validates. They were the same constant
 * here, and that is why this tree could not see the connection-ID rule at all: with one ID on both ends the ID
 * never has to change, so a client that kept sending to its own ID looked exactly like one that had adopted the
 * server's (WT-151). */
uint64_t build_parameters(uint8_t *out, size_t capacity, int is_server, const uint8_t *source,
                                 size_t source_length, const uint8_t *original_destination,
                                 size_t original_length, int retried,
                                 const uint8_t *retry_source, size_t retry_source_length) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(out, capacity);
  if (wt_quic_transport_parameters_build(&params, is_server, source, source_length, original_destination,
                                         original_length, retried, retry_source,
                                         retry_source_length) != WT_OK) {
    return 0U;
  }
  if (wt_quic_transport_parameters_encode(&w, &params) != WT_OK) return 0U;
  return (uint64_t)wt_writer_offset(&w);
}

void connection_config(wt_quic_connection_config_t *config, wt_quic_role_t role,
                              const uint8_t *connection_id, size_t connection_id_length) {
  memset(config, 0, sizeof(*config));
  config->role = role;
  config->version = WT_QUIC_VERSION_1;
  config->local_connection_id = connection_id;
  config->local_connection_id_length = connection_id_length;
  config->peer_connection_id = connection_id;
  config->peer_connection_id_length = connection_id_length;
  config->aead = WT_AEAD_AES_128_GCM;
  config->max_ack_delay = 25000U;
  config->local_max_ack_delay = 25000U;
  config->idle_timeout = 30000000U;
  config->max_datagram_size = 1200U;
}

/* Everything a failed run can say about WHY, read while the session is still alive.
 *
 * This was inline at each failure return once, and it was WRONG twice over: the assignments sat after
 * `wt_runtime_session_clear`, so the handshake state was read from a cleared struct (it said "idle" while the
 * connection held Handshake and Application keys), and the insertion loop left the block in some paths twice. A
 * helper called before the clear is one place, one order, and a comment that says why the order matters (WT-135).
 */
/* A frame the connection reported LOST, answered by sending the request again.
 *
 * RFC 9002 section 6.2.4: a probe timeout must send new frames or retransmit unacknowledged data. The connection
 * now reports the oldest outstanding frame to its owner (the runtime's lost-frame hook) and the HTTP/3 driver
 * retains what it sent, so this is the place the two meet -- and the place a packet lost between the handshake
 * and the response used to disappear for good (WT-135).
 *
 * Only the request stream is answered, and only when the driver has something retained: anything else is a frame
 * this tool has no bytes for, and saying so is better than sending something wrong. */
void client_on_lost_frame(void *context, const wt_quic_tx_frame_t *frame) {
  loop_t *loop = context;
  if (loop == NULL || frame == NULL) return;
  if (frame->is_crypto) return; /* the handshake retransmits its own */
  if (frame->stream_id != loop->side.request_stream_id) return;
  if (wt_http3_driver_resend_request(&loop->side.driver, &loop->transport, loop->now) == WT_OK) {
    loop->resends++;
  }
}

/* Whether this endpoint may SPEAK: the handshake is DONE and the peer's transport parameters are IN FORCE.
 *
 * Both halves are needed, and the measurement that showed it is this round's: breaking out on DONE alone made
 * the client start its CONNECT before the pump that applies the peer's parameters had run, so opening a request
 * stream was refused with WT_ERR_STATE (`"status":"state"`) while the session was already confirmed. The
 * parameters arrive in the same flight as the Finished and are applied by the NEXT pump, so the loop has to wait
 * for both (WT-142). */
int handshake_ready(const loop_t *loop) {
  return wt_runtime_session_handshake_done(&loop->session) != 0 &&
         loop->session.peer_parameters_applied != 0;
}

/* Whether this run ended with THIS endpoint having closed the connection, and why.
 *
 * A tool that answers "ok" here is lying: the peer was told the connection is over, whatever the exchange
 * counters say. It asks whether the close was SENT, not merely decided on -- the idle timeout closes silently
 * (RFC 9000 section 10.1), and a run whose only close is that one has told the peer nothing, so `WT_OK` is the
 * honest answer and `WT_ERR_PROTOCOL` would be an invented failure (WT-144, WT-145). The status the refusing
 * handler returned is the report when there was one, because it names the layer that refused. */
wt_status_t loop_close_status(const loop_t *loop) {
  if (wt_quic_connection_close_was_sent(&loop->session.connection) == 0) return WT_OK;
  if (loop->session.connection.close_cause != WT_OK) return loop->session.connection.close_cause;
  return WT_ERR_PROTOCOL;
}

/* The status a wait reports when it ended because the connection is CLOSED rather than because its deadline
 * passed, and whether that is what happened. A loop that kept pumping until its timeout after the transport was
 * already closed spent the caller's whole `--timeout-ms` to learn nothing -- and reported `timeout`, which is
 * precisely what did not happen (WT-147: the hostile-peer test waited five seconds for a refusal that had already
 * arrived). `loop_close_status` names the refusal when this endpoint sent one; WT_ERR_CLOSED is for a peer that
 * ended the connection while this one waited, which is still not a timeout. */
int loop_is_closed(const loop_t *loop) {
  return wt_quic_connection_is_closed(&loop->session.connection) != 0;
}

wt_status_t loop_wait_status(const loop_t *loop) {
  wt_status_t closed = loop_close_status(loop);
  return closed != WT_OK ? closed : WT_ERR_CLOSED;
}

void record_oracle(const loop_t *loop, wt_loop_result_t *out) {
  out->first_receive_error = loop->session.first_receive_error;
  out->receive_errors = loop->session.receive_errors;
  out->packets_seen = loop->session.packets_seen;
  out->last_receive = loop->session.last_receive;
  out->close_code = loop->session.connection.close_code;
  out->close_frame_type = loop->session.connection.close_frame_type;
  out->close_code_set = loop->session.connection.close_code_set;
  out->peer_error_code = loop->session.connection.peer_error_code;
  out->peer_closed = loop->session.connection.peer_closed;
  out->close_kind = (unsigned)loop->session.connection.close.kind;
  out->close_sent_error_code = loop->session.connection.close.error_code;
  out->close_sent_frame_type = loop->session.connection.close.frame_type;
  out->close_cause = loop->session.connection.close_cause;
  out->close_cause_frame = loop->session.connection.close_cause_frame;
  out->close_was_sent = wt_quic_connection_close_was_sent(&loop->session.connection);
  out->packets_discarded = loop->session.connection.packets_discarded;
  out->has_initial_keys = loop->session.connection.has_keys_in[WT_QUIC_SPACE_INITIAL];
  out->has_handshake_keys = loop->session.connection.has_keys_in[WT_QUIC_SPACE_HANDSHAKE];
  out->has_application_keys = loop->session.connection.has_keys_in[WT_QUIC_SPACE_APPLICATION];
  out->handshake_state = wt_quic_handshake_state_name(wt_quic_handshake_state(&loop->session.handshake));
  out->resends = loop->resends;
  out->probes = (unsigned)(loop->session.connection.probes_sent[WT_QUIC_SPACE_INITIAL] +
                           loop->session.connection.probes_sent[WT_QUIC_SPACE_HANDSHAKE] +
                           loop->session.connection.probes_sent[WT_QUIC_SPACE_APPLICATION]);
  out->probes_with_data = (unsigned)loop->session.connection.probes_with_data;
  out->acks_initial = (unsigned)loop->session.connection.acks_sent[WT_QUIC_SPACE_INITIAL];
  out->acks_handshake = (unsigned)loop->session.connection.acks_sent[WT_QUIC_SPACE_HANDSHAKE];
  out->acks_application = (unsigned)loop->session.connection.acks_sent[WT_QUIC_SPACE_APPLICATION];
  out->ack_largest_initial = loop->session.connection.ack_largest[WT_QUIC_SPACE_INITIAL];
  out->ack_largest_handshake = loop->session.connection.ack_largest[WT_QUIC_SPACE_HANDSHAKE];
  out->ack_largest_application = loop->session.connection.ack_largest[WT_QUIC_SPACE_APPLICATION];
  out->sent_initial = (unsigned)loop->session.connection.packets_sent_by_space[WT_QUIC_SPACE_INITIAL];
  out->sent_handshake = (unsigned)loop->session.connection.packets_sent_by_space[WT_QUIC_SPACE_HANDSHAKE];
  out->sent_application = (unsigned)loop->session.connection.packets_sent_by_space[WT_QUIC_SPACE_APPLICATION];
  out->acked_initial = (unsigned)loop->session.connection.packets_acked[WT_QUIC_SPACE_INITIAL];
  out->acked_handshake = (unsigned)loop->session.connection.packets_acked[WT_QUIC_SPACE_HANDSHAKE];
  out->acked_application = (unsigned)loop->session.connection.packets_acked[WT_QUIC_SPACE_APPLICATION];
  out->in_flight = (unsigned)wt_quic_loss_count(&loop->session.connection.loss);
  {
    const wt_tls13_transcript_t *transcript = NULL;
    size_t index;
    if (loop->session.connection.config.role == WT_QUIC_ROLE_CLIENT) {
      transcript = &loop->session.handshake.client.transcript;
    } else {
      transcript = &loop->session.handshake.server.transcript;
    }
    out->transcript_types_length = 0U;
    for (index = 0U; index < (size_t)transcript->messages && index < sizeof(out->transcript_types); index++) {
      out->transcript_types[index] = transcript->types[index];
      out->transcript_types_length = index + 1U;
    }
  }
  out->request_stream_id = loop->side.request_stream_id;
  out->streams_opened_bidi = (unsigned)loop->session.connection.streams.opened_by_us_bidi;
  out->streams_opened_uni = (unsigned)loop->session.connection.streams.opened_by_us_uni;
  /* Straight from the state the capsules moved, rather than from a counter of its own: a grant that was applied IS
   * the flow account, and a session the peer ended IS a close received with the code the first close carried. */
  out->peer_max_data_set = loop->side.capsules.peer_limits.max_data_set;
  out->peer_max_data = loop->side.capsules.peer_limits.max_data;
  out->peer_drained = loop->side.capsules.session.drain_received;
  out->peer_close_code_set = loop->side.capsules.session.close_received != 0 &&
                             loop->side.capsules.session.close_error_set != 0;
  out->peer_close_code = loop->side.capsules.session.close_error_code;
  out->capsules_refused = loop->side.capsules.refused;
  out->capsule_error = loop->side.capsule_error;
}

void pump_once(loop_t *loop) {
  (void)wt_udp_wait(&loop->socket, WT_LOOP_WAIT_MICROS);
  (void)wt_runtime_session_pump(&loop->session, loop->now);
  /* The capsule path may have to send a close, and a close is a frame with a time (WT-165). */
  loop->side.now_for_close = loop->now;
  loop->now += 1000U;
}

/* The message, on the mode the caller chose. A stream carries the draft's prefix and then the bytes, and the
 * stream is FINISHED with them: the Swift library's exchange opens a bidirectional stream and sends the message
 * with `endOfStream: true`, and a peer that reads a stream to its end cannot answer a message that never ends
 * (WT-135). The driver opens it, because the driver is what knows this endpoint owns the prefix -- the peer's
 * bytes on the same stream are payload, and an endpoint that re-read them as a prefix refuses its own answer. A
 * datagram carries the quarter stream ID and then the bytes, because a datagram IS the unit. */
wt_status_t send_message(loop_t *loop, const wt_http3_driver_transport_t *transport,
                                const wt_loop_config_t *config) {
  uint8_t framed[512];
  wt_writer_t w = wt_writer_init(framed, sizeof(framed));
  size_t message_length = config->message != NULL ? strlen(config->message) : 0U;

  if (config->datagram != 0) {
    if (wt_webtransport_datagram_write(&w, loop->side.request_stream_id / 4U,
                                       (const uint8_t *)config->message, message_length) != WT_OK) {
      return WT_ERR_LIMIT;
    }
    return transport->send_datagram(transport->context, framed, wt_writer_offset(&w));
  }
  return wt_http3_driver_open_data_stream(&loop->side.driver, transport, 0, (const uint8_t *)config->message,
                                          message_length, 1, loop->now, NULL);
}

