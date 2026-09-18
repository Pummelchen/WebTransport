/* Stream state machines and flow control.
 *
 * THE STATE MACHINE IS CHECKED AS A SEQUENCE OF LEGAL MOVES AND A SET OF ILLEGAL ONES, because the
 * errors it prevents are the ones that look like application bugs: writing after a FIN, sending a
 * second FIN with another size, and reading data as complete when the peer reset the stream. Each is
 * a transition this file refuses rather than a symptom the layer above has to interpret.
 *
 * THE FINAL SIZE IS CHECKED AS A BOUNDARY, because it is one: once the size is known, data at or
 * beyond it is a protocol error and a FIN that contradicts it is another. Without those two checks a
 * peer can append to a stream it has already ended, and a length-delimited protocol built on top of
 * QUIC reads the appended bytes as the next message.
 *
 * FLOW CONTROL IS CHECKED IN BOTH DIRECTIONS AND AT BOTH LEVELS. The connection's limit and the
 * stream's are each checked before a frame is written and each counted when one arrives, and the
 * interesting cases are the ones where only one of the two is exhausted: a stream with credit in a
 * connection without it cannot send, and a peer that writes past either limit is refused rather than
 * believed.
 */

#include "wt_test.h"

#include "webtransport/quic/stream.h"

#define WT_MAX_DATA 65536U
#define WT_MAX_STREAM_DATA 16384U
#define WT_PEER_MAX_DATA 65536U
#define WT_PEER_MAX_STREAM_DATA 16384U

static void init_stream(wt_quic_stream_t *stream) {
  wt_quic_stream_init(stream, 0U, 1, 1, WT_MAX_STREAM_DATA, WT_PEER_MAX_STREAM_DATA);
}

static void test_send_states(void) {
  wt_quic_stream_t stream;

  init_stream(&stream);
  WT_EXPECT_STR("a new stream is ready to send", "ready",
                wt_quic_send_state_name(stream.send_state));
  WT_EXPECT_STR("and receives", "recv", wt_quic_recv_state_name(stream.recv_state));
  WT_EXPECT_INT("with nothing finished", 0, wt_quic_stream_send_finished(&stream));
  WT_EXPECT_INT("and not complete", 0, wt_quic_stream_complete(&stream));

  /* The first byte moves it out of Ready. */
  WT_EXPECT_OK("a byte is sent", wt_quic_stream_on_data_sent(&stream, 1U));
  WT_EXPECT_STR("which moves the stream to send", "send",
                wt_quic_send_state_name(stream.send_state));
  WT_EXPECT_U64("and the offset follows", 1U, (uint64_t)stream.send_offset);

  /* A zero-length send does not move it, because an empty STREAM frame is not data. */
  {
    wt_quic_stream_t fresh;
    init_stream(&fresh);
    WT_EXPECT_OK("a zero-length send", wt_quic_stream_on_data_sent(&fresh, 0U));
    WT_EXPECT_STR("leaves the stream ready", "ready", wt_quic_send_state_name(fresh.send_state));
  }

  /* The FIN fixes the size and moves to Data Sent. */
  WT_EXPECT_OK("more data", wt_quic_stream_on_data_sent(&stream, 99U));
  WT_EXPECT_U64("at offset 100", 100U, (uint64_t)stream.send_offset);
  WT_EXPECT_OK("the FIN is sent", wt_quic_stream_on_fin_sent(&stream));
  WT_EXPECT_STR("moving to data sent", "data-sent", wt_quic_send_state_name(stream.send_state));
  WT_EXPECT_U64("with the stream's size fixed", 100U, (uint64_t)stream.final_size);
  WT_EXPECT_INT("and the send half finished", 1, wt_quic_stream_send_finished(&stream));

  /* Nothing more may be written, and a second FIN is refused. */
  WT_EXPECT_STATUS("data after the FIN is refused", WT_ERR_STATE,
                   wt_quic_stream_on_data_sent(&stream, 1U));
  WT_EXPECT_STATUS("a second FIN is refused", WT_ERR_STATE, wt_quic_stream_on_fin_sent(&stream));

  /* Acknowledging part of it does not complete the stream; acknowledging all of it does. */
  WT_EXPECT_OK("half is acknowledged", wt_quic_stream_on_ack(&stream, 50U));
  WT_EXPECT_STR("which leaves it data sent", "data-sent",
                wt_quic_send_state_name(stream.send_state));
  WT_EXPECT_OK("and the rest", wt_quic_stream_on_ack(&stream, 100U));
  WT_EXPECT_STR("which completes the send half", "data-received",
                wt_quic_send_state_name(stream.send_state));
  /* A late acknowledgement for an earlier offset does not move the watermark backwards. */
  WT_EXPECT_OK("an older acknowledgement", wt_quic_stream_on_ack(&stream, 40U));
  WT_EXPECT_U64("does not move the watermark", 100U, (uint64_t)stream.send_acked);
}

static void test_reset_and_stop(void) {
  wt_quic_stream_t stream;

  /* A reset ends the send half at whatever had been sent. */
  init_stream(&stream);
  WT_EXPECT_OK("some data is sent", wt_quic_stream_on_data_sent(&stream, 30U));
  WT_EXPECT_OK("and the stream is reset", wt_quic_stream_on_reset_sent(&stream, 7U));
  WT_EXPECT_STR("which finishes the send half", "reset-sent",
                wt_quic_send_state_name(stream.send_state));
  WT_EXPECT_U64("at the size that was sent", 30U, (uint64_t)stream.final_size);
  WT_EXPECT_STATUS("and no more data may be sent", WT_ERR_STATE,
                   wt_quic_stream_on_data_sent(&stream, 1U));
  /* Its acknowledgement completes the send half rather than leaving it in Reset Sent forever. */
  WT_EXPECT_OK("the reset is acknowledged", wt_quic_stream_on_ack(&stream, 30U));
  WT_EXPECT_STR("completing it", "reset-received", wt_quic_send_state_name(stream.send_state));

  /* STOP_SENDING finishes the send half as the reset does, so a caller that forgets to send the
   * RESET_STREAM cannot keep writing to a stream the peer has abandoned. */
  init_stream(&stream);
  WT_EXPECT_OK("some data is sent", wt_quic_stream_on_data_sent(&stream, 10U));
  WT_EXPECT_OK("the peer asks to stop", wt_quic_stream_on_stop_sending(&stream, 3U));
  WT_EXPECT_INT("which finishes the send half", 1, wt_quic_stream_send_finished(&stream));
  WT_EXPECT_STR("as a reset sent", "reset-sent", wt_quic_send_state_name(stream.send_state));
  WT_EXPECT_STATUS("so nothing more may be sent", WT_ERR_STATE,
                   wt_quic_stream_on_data_sent(&stream, 1U));

  /* A received reset: the receive half is finished, and the final size it carries has to agree with
   * anything already known. */
  init_stream(&stream);
  WT_EXPECT_OK("a reset arrives", wt_quic_stream_on_reset_received(&stream, 9U, 100U));
  WT_EXPECT_STR("which the receive half records", "reset-received",
                wt_quic_recv_state_name(stream.recv_state));
  /* The reset has arrived but the application has not been told, so the stream is not finished: a
   * connection that treated the two as the same thing would forget a stream the application is still
   * waiting on. */
  WT_EXPECT_INT("but the stream is not finished yet", 0, wt_quic_stream_recv_finished(&stream));
  WT_EXPECT_INT("and the peer's error is kept", 9, (int)stream.peer_error_code);
  WT_EXPECT_STATUS("a second reset with another size is refused", WT_ERR_PROTOCOL,
                   wt_quic_stream_on_reset_received(&stream, 9U, 50U));
  WT_EXPECT_STATUS("reading a reset stream is refused", WT_ERR_STATE,
                   wt_quic_stream_on_data_read(&stream, 1U));
  WT_EXPECT_STATUS("and telling the application completes it", WT_OK,
                   wt_quic_stream_on_reset_read(&stream));
  WT_EXPECT_STR("moving to reset read", "reset-read", wt_quic_recv_state_name(stream.recv_state));
  WT_EXPECT_INT("which is finished", 1, wt_quic_stream_recv_finished(&stream));
  WT_EXPECT_STATUS("telling it twice is refused", WT_ERR_STATE,
                   wt_quic_stream_on_reset_read(&stream));

  /* A FIN that contradicts a known size is refused as well, and the flow block is passed because a
   * NULL one would be refused before the size is ever looked at. */
  {
    wt_quic_stream_t fin;
    wt_quic_flow_t flow;
    uint64_t credit = 0U;
    int in_order = 0;
    init_stream(&fin);
    wt_quic_flow_init(&flow, WT_MAX_DATA, WT_PEER_MAX_DATA);
    WT_EXPECT_OK("three bytes and a FIN",
                 wt_quic_stream_on_data(&fin, &flow, 0U, 3U, 1, &credit, &in_order));
    WT_EXPECT_STATUS("a FIN for another size is refused", WT_ERR_PROTOCOL,
                     wt_quic_stream_on_data(&fin, &flow, 3U, 1U, 1, &credit, &in_order));
  }
}

static void test_final_size(void) {
  wt_quic_stream_t stream;
  wt_quic_flow_t flow;
  uint64_t new_bytes = 0U;
  int in_order = 0;

  init_stream(&stream);
  wt_quic_flow_init(&flow, WT_MAX_DATA, WT_PEER_MAX_DATA);

  /* Three bytes with a FIN: the size is three. */
  WT_EXPECT_OK("three bytes and a FIN",
               wt_quic_stream_on_data(&stream, &flow, 0U, 3U, 1, &new_bytes, &in_order));
  WT_EXPECT_U64("all three are new", 3U, new_bytes);
  WT_EXPECT_INT("and arrive in order", 1, in_order);
  WT_EXPECT_U64("the final size is three", 3U, (uint64_t)stream.recv_final_size);
  WT_EXPECT_STR("and the size is known", "data-received",
                wt_quic_recv_state_name(stream.recv_state));

  /* A retransmission of the same bytes is not an error and is not new. */
  WT_EXPECT_OK("the same bytes again",
               wt_quic_stream_on_data(&stream, &flow, 0U, 3U, 1, &new_bytes, &in_order));
  WT_EXPECT_U64("with nothing new", 0U, new_bytes);

  /* Data beyond the final size is a protocol error, whether it arrives as its own frame or as an
   * overlap that reaches past the end. */
  {
    wt_quic_stream_t bounded;
    init_stream(&bounded);
    WT_EXPECT_OK("three bytes and a FIN",
                 wt_quic_stream_on_data(&bounded, &flow, 0U, 3U, 1, &new_bytes, &in_order));
    WT_EXPECT_STATUS("data beyond the end is refused", WT_ERR_PROTOCOL,
                     wt_quic_stream_on_data(&bounded, &flow, 3U, 1U, 0, &new_bytes, &in_order));
    WT_EXPECT_STATUS("and an overlap that reaches past it", WT_ERR_PROTOCOL,
                     wt_quic_stream_on_data(&bounded, &flow, 2U, 2U, 0, &new_bytes, &in_order));
    /* A FIN that claims a different size is the same error by another route. */
    WT_EXPECT_STATUS("a FIN for another size is refused", WT_ERR_PROTOCOL,
                     wt_quic_stream_on_data(&bounded, &flow, 5U, 0U, 1, &new_bytes, &in_order));
  }

  /* A stream whose size is known from a RESET_STREAM refuses later data as well. */
  {
    wt_quic_stream_t reset;
    init_stream(&reset);
    WT_EXPECT_OK("a reset arrives with a size", wt_quic_stream_on_reset_received(&reset, 1U, 8U));
    WT_EXPECT_STATUS("data past that size is refused", WT_ERR_PROTOCOL,
                     wt_quic_stream_on_data(&reset, &flow, 8U, 1U, 0, &new_bytes, &in_order));
  }

  /* The offset arithmetic is checked before it can wrap. */
  {
    wt_quic_stream_t huge;
    init_stream(&huge);
    WT_EXPECT_STATUS(
        "an offset near the top of the range is refused", WT_ERR_PROTOCOL,
        wt_quic_stream_on_data(&huge, &flow, UINT64_MAX - 1U, 4U, 0, &new_bytes, &in_order));
  }
}

static void test_flow_control(void) {
  wt_quic_stream_t stream;
  wt_quic_flow_t flow;
  uint64_t new_bytes = 0U;
  int in_order = 0;

  init_stream(&stream);
  wt_quic_flow_init(&flow, WT_MAX_DATA, WT_PEER_MAX_DATA);
  WT_EXPECT_U64("a new stream may send its whole limit", WT_PEER_MAX_STREAM_DATA,
                wt_quic_stream_send_allowance(&stream, &flow));
  WT_EXPECT_INT("so a datagram fits", 1, wt_quic_stream_can_send(&stream, &flow, 1200U));

  /* The stream's own limit runs out first. */
  WT_EXPECT_OK("the stream's limit is consumed", wt_quic_stream_on_data_sent(&stream, 16384U));
  WT_EXPECT_U64("leaving no stream credit", 0U, wt_quic_stream_send_allowance(&stream, &flow));
  WT_EXPECT_INT("so nothing may be sent", 0, wt_quic_stream_can_send(&stream, &flow, 1U));
  /* The connection's limit is untouched, which is what makes the two limits two limits. */
  WT_EXPECT_U64("while the connection still has credit", WT_PEER_MAX_DATA,
                wt_quic_flow_send_allowance(&flow));

  /* The peer raises the stream limit: sending is possible again, and a limit that goes backwards is
   * refused. */
  WT_EXPECT_STATUS("a lower stream limit is refused", WT_ERR_PROTOCOL,
                   wt_quic_stream_on_max_stream_data(&stream, 1000U));
  WT_EXPECT_OK("a higher one is accepted", wt_quic_stream_on_max_stream_data(&stream, 32768U));
  WT_EXPECT_U64("giving the difference", 32768U - 16384U,
                wt_quic_stream_send_allowance(&stream, &flow));

  /* The connection's limit can be the binding constraint even when the stream has credit. */
  {
    wt_quic_stream_t small;
    wt_quic_flow_t narrow;
    init_stream(&small);
    wt_quic_flow_init(&narrow, WT_MAX_DATA, 100U);
    WT_EXPECT_U64("the connection's limit binds", 100U,
                  wt_quic_stream_send_allowance(&small, &narrow));
    WT_EXPECT_INT("so a large frame does not fit", 0,
                  wt_quic_stream_can_send(&small, &narrow, 1200U));
    WT_EXPECT_INT("while a small one does", 1, wt_quic_stream_can_send(&small, &narrow, 100U));
    WT_EXPECT_OK("sending it consumes both", wt_quic_flow_on_sent(&narrow, 100U));
    WT_EXPECT_U64("leaving the connection empty", 0U,
                  wt_quic_stream_send_allowance(&small, &narrow));
    /* And the connection's limit may only be raised too. */
    WT_EXPECT_STATUS("a lower connection limit is refused", WT_ERR_PROTOCOL,
                     wt_quic_flow_on_max_data(&narrow, 50U));
    WT_EXPECT_OK("a higher one is accepted", wt_quic_flow_on_max_data(&narrow, 200U));
    /* A hundred bytes have been sent, so a limit of two hundred leaves a hundred to send. */
    WT_EXPECT_U64("and the allowance follows", 100U, wt_quic_flow_send_allowance(&narrow));
  }

  /* On the receiving side, the stream's limit and the connection's are both bounds, and the
   * connection counts bytes that arrive out of order too. */
  {
    wt_quic_stream_t receive;
    wt_quic_flow_t inbound;
    init_stream(&receive);
    wt_quic_flow_init(&inbound, 1000U, WT_PEER_MAX_DATA);
    /* The stream may take up to 16384 but the connection only advertised 1000. */
    WT_EXPECT_STATUS(
        "more than the connection advertised is refused", WT_ERR_PROTOCOL,
        wt_quic_stream_on_data(&receive, &inbound, 0U, 1200U, 0, &new_bytes, &in_order));
    WT_EXPECT_OK("what fits is accepted",
                 wt_quic_stream_on_data(&receive, &inbound, 0U, 800U, 0, &new_bytes, &in_order));
    WT_EXPECT_U64("and counted", 800U, (uint64_t)inbound.data_received);
    WT_EXPECT_INT("with the connection needing an extension", 0,
                  wt_quic_flow_should_extend(&inbound));
    WT_EXPECT_OK("more arrives",
                 wt_quic_stream_on_data(&receive, &inbound, 800U, 200U, 0, &new_bytes, &in_order));
    WT_EXPECT_INT("which reaches the advertised limit", 1, wt_quic_flow_should_extend(&inbound));
    WT_EXPECT_U64("so the next limit is the window past it", 1000U + 500U,
                  wt_quic_flow_next_max_data(&inbound));
    wt_quic_flow_on_max_data_sent(&inbound, wt_quic_flow_next_max_data(&inbound));
    WT_EXPECT_U64("and is advertised", 1500U, (uint64_t)inbound.max_data);
  }

  /* The stream's own receive limit binds independently of the connection's. */
  {
    wt_quic_stream_t narrow_stream;
    wt_quic_flow_t wide;
    wt_quic_stream_init(&narrow_stream, 4U, 0, 1, 100U, WT_PEER_MAX_STREAM_DATA);
    wt_quic_flow_init(&wide, WT_MAX_DATA, WT_PEER_MAX_DATA);
    WT_EXPECT_OK("a frame inside the stream's limit",
                 wt_quic_stream_on_data(&narrow_stream, &wide, 0U, 100U, 0, &new_bytes, &in_order));
    WT_EXPECT_INT("reaches it", 1, wt_quic_stream_should_extend(&narrow_stream));
    WT_EXPECT_STATUS(
        "and the next byte is refused", WT_ERR_PROTOCOL,
        wt_quic_stream_on_data(&narrow_stream, &wide, 100U, 1U, 0, &new_bytes, &in_order));
    WT_EXPECT_U64("with the next limit a window later", 100U + 50U,
                  wt_quic_stream_next_max_stream_data(&narrow_stream));
  }
}

static void test_receiving_states(void) {
  wt_quic_stream_t stream;
  wt_quic_flow_t flow;
  uint64_t new_bytes = 0U;
  int in_order = 0;

  init_stream(&stream);
  wt_quic_flow_init(&flow, WT_MAX_DATA, WT_PEER_MAX_DATA);

  /* Data arrives out of order: it is accepted, and its cost is the maximum offset it establishes
   * rather than its length, which is how RFC 9000 section 4.1 keeps a gap from escaping the
   * accounting. */
  WT_EXPECT_OK("ten bytes at offset 100",
               wt_quic_stream_on_data(&stream, &flow, 100U, 10U, 0, &new_bytes, &in_order));
  WT_EXPECT_U64("costing the whole offset", 110U, new_bytes);
  WT_EXPECT_INT("and out of order", 0, in_order);
  WT_EXPECT_U64("with the highest offset recorded", 110U, (uint64_t)stream.recv_highest);
  WT_EXPECT_U64("and nothing delivered yet", 0U, (uint64_t)stream.recv_offset);

  /* A retransmission of those ten bytes costs nothing, because the maximum offset does not move. */
  WT_EXPECT_OK("the same ten bytes again",
               wt_quic_stream_on_data(&stream, &flow, 100U, 10U, 0, &new_bytes, &in_order));
  WT_EXPECT_U64("costing nothing", 0U, new_bytes);

  /* The missing bytes arrive with the FIN, which covers the whole stream and so completes it. A FIN
   * that claimed a smaller size would contradict the bytes already seen. */
  WT_EXPECT_OK("a hundred and ten bytes at offset 0 with a FIN",
               wt_quic_stream_on_data(&stream, &flow, 0U, 110U, 1, &new_bytes, &in_order));
  WT_EXPECT_U64("costing nothing more", 0U, new_bytes);
  WT_EXPECT_INT("and in order", 1, in_order);
  WT_EXPECT_U64("the final size is 110", 110U, (uint64_t)stream.recv_final_size);
  /* Nothing is beyond the final size, but the highest offset is only 110 once the frame is counted:
   * the state becomes complete when everything up to the size has arrived. */
  WT_EXPECT_STR("and the body has all arrived", "data-received",
                wt_quic_recv_state_name(stream.recv_state));

  /* Reading it moves to Data Read, and the stream is finished. */
  WT_EXPECT_OK("the application reads ten bytes", wt_quic_stream_on_data_read(&stream, 10U));
  WT_EXPECT_U64("advancing the delivered offset", 10U, (uint64_t)stream.recv_offset);
  WT_EXPECT_STR("but not completing it", "data-received",
                wt_quic_recv_state_name(stream.recv_state));
  WT_EXPECT_OK("reading the rest", wt_quic_stream_on_data_read(&stream, 100U));
  WT_EXPECT_STR("completes the receive half", "data-read",
                wt_quic_recv_state_name(stream.recv_state));
  WT_EXPECT_INT("which is finished", 1, wt_quic_stream_recv_finished(&stream));
  /* Reading more than arrived is a caller error rather than a peer's. */
  WT_EXPECT_STATUS("reading past what arrived is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_stream_on_data_read(&stream, 1U));
}

/* The four fields in a stream number (RFC 9000 section 2.1), which every rule about streams reads. */
static void test_stream_id_fields(void) {
  uint64_t id;

  WT_EXPECT_U64("a client's bidirectional stream 3", 12U, wt_quic_stream_id_make(1, 1, 3U));
  WT_EXPECT_U64("a server's bidirectional stream 0", 1U, wt_quic_stream_id_make(0, 1, 0U));
  WT_EXPECT_U64("a client's unidirectional stream 0", 2U, wt_quic_stream_id_make(1, 0, 0U));
  WT_EXPECT_U64("a server's unidirectional stream 0", 3U, wt_quic_stream_id_make(0, 0, 0U));
  WT_EXPECT_INT("stream 0 is the client's", 1, wt_quic_stream_id_from_client(0U));
  WT_EXPECT_INT("stream 1 is the server's", 0, wt_quic_stream_id_from_client(1U));
  WT_EXPECT_INT("stream 0 is bidirectional", 1, wt_quic_stream_id_is_bidirectional(0U));
  WT_EXPECT_INT("stream 2 is not", 0, wt_quic_stream_id_is_bidirectional(2U));
  WT_EXPECT_U64("stream 12 is index 3", 3U, wt_quic_stream_id_index(12U));

  for (id = 0U; id < 16U; id++) {
    uint64_t rebuilt =
        wt_quic_stream_id_make(wt_quic_stream_id_from_client(id),
                               wt_quic_stream_id_is_bidirectional(id), wt_quic_stream_id_index(id));
    WT_EXPECT_U64("and every number is the one its fields describe", id, rebuilt);
  }
}

/* The stream table: bounded, per-class counts, and the refusal that keeps a peer from choosing this
 * endpoint's memory. */
static void test_stream_table(void) {
  wt_quic_stream_table_t table;
  wt_quic_stream_t *stream;
  uint64_t i;

  wt_quic_stream_table_init(&table);
  WT_EXPECT_U64("a fresh table is empty", 0U, (uint64_t)wt_quic_stream_table_count(&table));
  WT_EXPECT_TRUE("and holds nothing", wt_quic_stream_table_find(&table, 0U) == NULL);

  for (i = 0U; i < 4U; i++) {
    WT_EXPECT_OK("a stream opens",
                 wt_quic_stream_table_open(&table, wt_quic_stream_id_make(1, 1, i), 1, 4U));
  }
  WT_EXPECT_U64("four are live", 4U, (uint64_t)wt_quic_stream_table_count(&table));
  WT_EXPECT_U64("and counted for this endpoint", 4U, wt_quic_stream_table_opened_by_us(&table, 1));
  WT_EXPECT_STATUS("a fifth is beyond the limit", WT_ERR_LIMIT,
                   wt_quic_stream_table_open(&table, wt_quic_stream_id_make(1, 1, 4U), 1, 4U));
  WT_EXPECT_STATUS("and opening one twice is a state error", WT_ERR_STATE,
                   wt_quic_stream_table_open(&table, wt_quic_stream_id_make(1, 1, 0U), 1, 8U));

  stream = wt_quic_stream_table_find(&table, wt_quic_stream_id_make(1, 1, 2U));
  WT_EXPECT_TRUE("a stream is found by number", stream != NULL);
  if (stream != NULL) {
    WT_EXPECT_U64("with the number it was opened with", wt_quic_stream_id_make(1, 1, 2U),
                  stream->id);
    WT_EXPECT_INT("as this endpoint's", 1, stream->initiated_by_us);
    WT_EXPECT_INT("and bidirectional", 1, stream->bidirectional);
  }
  WT_EXPECT_TRUE("an unopened number is not in the table",
                 wt_quic_stream_table_find(&table, wt_quic_stream_id_make(1, 1, 9U)) == NULL);

  WT_EXPECT_OK("a unidirectional stream opens",
               wt_quic_stream_table_open(&table, wt_quic_stream_id_make(1, 0, 0U), 1, 4U));
  WT_EXPECT_U64("counted on its own", 1U, wt_quic_stream_table_opened_by_us(&table, 0));
  WT_EXPECT_U64("leaving the bidirectional count alone", 4U,
                wt_quic_stream_table_opened_by_us(&table, 1));
  WT_EXPECT_STATUS("a peer's stream needs the peer's allowance", WT_ERR_LIMIT,
                   wt_quic_stream_table_open(&table, wt_quic_stream_id_make(0, 1, 0U), 0, 0U));
  WT_EXPECT_OK("which it has when it granted one",
               wt_quic_stream_table_open(&table, wt_quic_stream_id_make(0, 1, 0U), 0, 1U));
  WT_EXPECT_U64("and that is counted for the peer", 1U,
                wt_quic_stream_table_opened_by_peer(&table, 1));
  WT_EXPECT_U64("not for this endpoint", 4U, wt_quic_stream_table_opened_by_us(&table, 1));

  WT_EXPECT_STATUS("an unfinished stream stays in the table", WT_ERR_STATE,
                   wt_quic_stream_table_close(&table, wt_quic_stream_id_make(1, 1, 0U)));
  WT_EXPECT_STATUS("and closing nothing is a state error", WT_ERR_STATE,
                   wt_quic_stream_table_close(&table, wt_quic_stream_id_make(1, 1, 9U)));

  {
    wt_quic_stream_table_t small;
    wt_quic_stream_table_init(&small);
    for (i = 0U; i < WT_QUIC_STREAM_TABLE_MAX; i++) {
      WT_EXPECT_OK("the table fills",
                   wt_quic_stream_table_open(&small, wt_quic_stream_id_make(1, 1, i), 1, 1000U));
    }
    WT_EXPECT_U64("to its bound", (uint64_t)WT_QUIC_STREAM_TABLE_MAX,
                  (uint64_t)wt_quic_stream_table_count(&small));
    WT_EXPECT_STATUS("and refuses one more", WT_ERR_LIMIT,
                     wt_quic_stream_table_open(
                         &small, wt_quic_stream_id_make(1, 1, WT_QUIC_STREAM_TABLE_MAX), 1, 1000U));
  }

  WT_EXPECT_STATUS("a null table is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_stream_table_open(NULL, 0U, 1, 1U));
  WT_EXPECT_U64("and has no count", 0U, (uint64_t)wt_quic_stream_table_count(NULL));
  WT_EXPECT_TRUE("nor streams", wt_quic_stream_table_at(NULL, 0U) == NULL);
  WT_EXPECT_TRUE("nor a const find", wt_quic_stream_table_find_const(NULL, 0U) == NULL);
}

/* End both halves of a stream so the table may forget it. The FIN ends the send half; the receive half is
 * ended the other way RFC 9000 section 3.2 allows, by a reset the application has been told about. */
static void complete_table_stream(wt_quic_stream_t *stream) {
  WT_EXPECT_STATUS("the send half ends", WT_OK, wt_quic_stream_on_fin_sent(stream));
  WT_EXPECT_STATUS("and the peer resets the receive half", WT_OK,
                   wt_quic_stream_on_reset_received(stream, 0U, 0U));
  WT_EXPECT_STATUS("which the application is told about", WT_OK,
                   wt_quic_stream_on_reset_read(stream));
  WT_EXPECT_TRUE("so the stream is complete", wt_quic_stream_complete(stream));
}

/* RFC 9000 section 2.1: "A QUIC endpoint MUST NOT reuse a stream ID". The opened counts are what name the
 * numbers -- `wt_quic_connection_open_stream` builds the next number from them -- so reclaiming a finished
 * stream's SLOT must not take its NUMBER back out of circulation. Before this the reclaim decremented the
 * count, so it fell below the numbers already in use; the next open read the count, rebuilt a number a
 * completed stream had held, and because the reclaim had just freed a slot the table accepted it instead of
 * reporting a duplicate. Two streams then shared one number. */
static void test_stream_table_reclaim_keeps_ids_new(void) {
  wt_quic_stream_table_t table;
  uint64_t highest = 0U;
  uint64_t i;
  int have_highest = 0;

  wt_quic_stream_table_init(&table);
  /* More opens than the table has slots, so a reclaim happens mid-run and the number after it is the one
   * under test; every slot is reclaimable because each stream is completed as soon as it opens. */
  for (i = 0U; i < (uint64_t)WT_QUIC_STREAM_TABLE_MAX + 2U; i++) {
    uint64_t index = wt_quic_stream_table_opened_by_us(&table, 1);
    uint64_t id = wt_quic_stream_id_make(1, 1, index);
    wt_quic_stream_t *stream;

    WT_EXPECT_OK("a stream opens", wt_quic_stream_table_open(&table, id, 1, 1000U));
    if (have_highest) {
      WT_EXPECT_TRUE("and its number is one no earlier stream used", id > highest);
    }
    highest = id;
    have_highest = 1;
    WT_EXPECT_U64("the run of opened numbers only grows", (uint64_t)(i + 1U),
                  wt_quic_stream_table_opened_by_us(&table, 1));

    stream = wt_quic_stream_table_find(&table, id);
    WT_EXPECT_TRUE("the stream is in the table", stream != NULL);
    if (stream != NULL) complete_table_stream(stream);
  }
}

int main(void) {
  test_send_states();
  test_reset_and_stop();
  test_final_size();
  test_flow_control();
  test_receiving_states();

  test_stream_id_fields();
  test_stream_table();
  test_stream_table_reclaim_keeps_ids_new();
  WT_TEST_MAIN_END("wt_quic_stream");
}
