#include "test_http3_driver_internal.h"

void test_a_prefix_split_across_frames(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t prefix[8];
  size_t prefix_length;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  /* The draft's WebTransport stream type, 0x54, is one byte -- so the split is tested with a
   * type whose varint is longer. 0x1f * 0x21 + 0x21 is a reserved HTTP/2-era type this build
   * does not know: two bytes, and the first byte says so. */
  prefix_length = wt_quic_varint_encode((1U << 6) + 5U, prefix, sizeof(prefix));
  WT_EXPECT_U64("the test's type takes two bytes", 2U, (uint64_t)prefix_length);

  /* The first frame carries only the first byte: nothing is classified yet, and the driver
   * holds exactly that byte. */
  WT_EXPECT_OK("half a prefix is accepted",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, prefix, 1U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_INT("with nothing classified", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN, (int)kind);
  WT_EXPECT_U64("no payload", 0U, (uint64_t)payload_length);
  WT_EXPECT_U64("and one byte held", 1U, (uint64_t)wt_http3_driver_pending_count(&driver));

  /* The second frame completes it and carries session data behind it. */
  {
    uint8_t frame[16];
    size_t i;
    frame[0] = prefix[1];
    for (i = 1U; i < sizeof(frame); i++)
      frame[i] = 0xa0U + (uint8_t)i;
    WT_EXPECT_OK("the rest of the prefix completes it",
                 wt_http3_driver_on_uni_stream_data(&driver, 3U, 1U, frame, sizeof(frame), &kind,
                                                    &payload, &payload_length, &consumed, &error));
    WT_EXPECT_INT("classifying the stream", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN, (int)kind);
    WT_EXPECT_U64("with one byte of this frame taken for it", 1U, (uint64_t)consumed);
    WT_EXPECT_U64("leaving the rest as payload", (uint64_t)(sizeof(frame) - 1U),
                  (uint64_t)payload_length);
    WT_EXPECT_TRUE("as a view into the frame", payload == frame + 1);
    WT_EXPECT_U64("starting with its first payload byte", (uint64_t)frame[1], (uint64_t)payload[0]);
  }
  WT_EXPECT_U64("and nothing left pending", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
}

void test_a_complete_prefix_in_one_frame(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t frame[8];
  size_t frame_length = 0U;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  /* The draft's stream type spelled as a varint rather than assumed to be one byte: 0x54 has
   * its top bits set, so it is a TWO-byte varint, and a test that wrote it as one byte would
   * be testing the wrong stream type. */
  frame_length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, frame, sizeof(frame));
  /* The draft's prefix is the TYPE and then the session ID, so the payload starts after both: a test that
   * omitted the session ID would be asserting that a byte of it is session data. */
  frame_length += wt_quic_varint_encode(0U, frame + frame_length, sizeof(frame) - frame_length);
  frame[frame_length] = 0x11U;
  frame[frame_length + 1U] = 0x22U;
  frame[frame_length + 2U] = 0x33U;
  frame_length += 3U;

  WT_EXPECT_OK("a whole prefix is classified at once",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, frame, frame_length, &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as the session layer's stream", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT,
                (int)kind);
  WT_EXPECT_U64("with the type's two bytes and the session ID's one accounted for", 3U,
                (uint64_t)consumed);
  WT_EXPECT_U64("and three of payload", 3U, (uint64_t)payload_length);
  WT_EXPECT_TRUE("viewed in place, after both parts of the prefix", payload == frame + 3U);

  /* A second WebTransport stream is allowed: the draft bounds them by the session's own
   * stream table, not by "one per connection". */
  WT_EXPECT_OK("a second one is classified too",
               wt_http3_driver_on_uni_stream_data(&driver, 7U, 0U, frame, frame_length, &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as the same kind", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);

  /* A prefix that does not start at offset zero is the caller's accounting: the first byte of
   * the varint is what says how long it is, and a caller that lost it cannot be helped by
   * guessing. */
  WT_EXPECT_STATUS("a prefix that starts late is the caller's error", WT_ERR_STATE,
                   wt_http3_driver_on_uni_stream_data(&driver, 11U, 1U, frame, frame_length, &kind,
                                                      &payload, &payload_length, &consumed,
                                                      &error));

  /* Resuming a stream at the wrong offset is the same class of mistake. */
  {
    uint8_t two[2];
    two[0] = (uint8_t)((1U << 6) | 1U); /* a two-byte varint's first byte */
    two[1] = 0x00U;
    WT_EXPECT_OK("a stream may wait for its prefix",
                 wt_http3_driver_on_uni_stream_data(&driver, 15U, 0U, two, 1U, &kind, &payload,
                                                    &payload_length, &consumed, &error));
    WT_EXPECT_STATUS("but not resume out of order", WT_ERR_STATE,
                     wt_http3_driver_on_uni_stream_data(&driver, 15U, 2U, two, 1U, &kind, &payload,
                                                        &payload_length, &consumed, &error));
    WT_EXPECT_OK("and its end drops it", wt_http3_driver_on_uni_stream_end(&driver, 15U, &error));
    WT_EXPECT_U64("leaving nothing pending", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
  }

  /* An empty frame adds nothing and classifies nothing. */
  WT_EXPECT_OK("an empty frame is nothing",
               wt_http3_driver_on_uni_stream_data(&driver, 19U, 0U, NULL, 0U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_U64("with nothing pending", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
}

void test_control_and_qpack_reach_the_endpoint(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t frame[2];

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);

  frame[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
  frame[1] = 0x00U;
  WT_EXPECT_OK("the peer's control stream is classified",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, frame, sizeof(frame), &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as control", (int)WT_HTTP3_ENDPOINT_STREAM_CONTROL, (int)kind);

  /* The endpoint's one-per-connection rule is applied through the driver: a second control
   * stream is a connection error, with the code the RFC names. */
  WT_EXPECT_STATUS("and a second one is refused", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_data(&driver, 7U, 0U, frame, sizeof(frame), &kind,
                                                      &payload, &payload_length, &consumed,
                                                      &error));
  WT_EXPECT_U64("with the stream creation code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  /* Ending the control stream is the error itself, and the driver passes that through. */
  WT_EXPECT_STATUS("closing it is an error", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_end(&driver, 3U, &error));
  WT_EXPECT_U64("with the closed-critical-stream code", WT_HTTP3_CLOSED_CRITICAL_STREAM,
                (uint64_t)error);

  /* A QPACK stream, and then a second of the same kind. */
  frame[0] = (uint8_t)WT_HTTP3_STREAM_QPACK_ENCODER;
  WT_EXPECT_OK("the QPACK encoder stream is classified",
               wt_http3_driver_on_uni_stream_data(&driver, 11U, 0U, frame, 1U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_INT("as the encoder", (int)WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, (int)kind);
  WT_EXPECT_STATUS("and only one is allowed", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_data(&driver, 15U, 0U, frame, 1U, &kind, &payload,
                                                      &payload_length, &consumed, &error));
  /* And ending it IS one: RFC 9204 section 4.2 makes the QPACK encoder stream critical, so closing it is
   * H3_CLOSED_CRITICAL_STREAM -- the same answer the control stream gets two cases above. This assertion used to
   * read `WT_EXPECT_OK("ending it is not an error")`, which was the defect written down as a test: a peer could
   * close the stream its instructions were arriving on and this endpoint would carry on as though the dynamic
   * table were still in sync. An audit filed it (finding 11) and the endpoint now refuses it. */
  WT_EXPECT_STATUS("ending it is an error", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_end(&driver, 11U, &error));
  WT_EXPECT_U64("with the closed-critical-stream code", WT_HTTP3_CLOSED_CRITICAL_STREAM,
                (uint64_t)error);
}

void test_the_pending_table_is_bounded(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t half = 0xc0U; /* a four-byte varint's first byte */
  size_t i;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  for (i = 0U; i < (size_t)WT_HTTP3_DRIVER_PENDING_MAX; i++) {
    WT_EXPECT_OK("a stream waits for its prefix",
                 wt_http3_driver_on_uni_stream_data(&driver, 4U + (uint64_t)i * 4U, 0U, &half, 1U,
                                                    &kind, &payload, &payload_length, &consumed,
                                                    &error));
  }
  WT_EXPECT_U64("the table is full", (uint64_t)WT_HTTP3_DRIVER_PENDING_MAX,
                (uint64_t)wt_http3_driver_pending_count(&driver));

  /* One more opening stream is THIS endpoint's bound: WT_ERR_LIMIT with no error code, because
   * a peer that opens streams is doing nothing wrong. */
  WT_EXPECT_STATUS("one more is limited", WT_ERR_LIMIT,
                   wt_http3_driver_on_uni_stream_data(&driver, 4096U, 0U, &half, 1U, &kind,
                                                      &payload, &payload_length, &consumed,
                                                      &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);

  /* Ending a waiting stream frees its slot, so the bound is about concurrency rather than a
   * lifetime total. */
  WT_EXPECT_OK("a waiting stream may end", wt_http3_driver_on_uni_stream_end(&driver, 4U, &error));
  WT_EXPECT_U64("freeing its slot", (uint64_t)(WT_HTTP3_DRIVER_PENDING_MAX - 1U),
                (uint64_t)wt_http3_driver_pending_count(&driver));
  WT_EXPECT_OK("so another may wait",
               wt_http3_driver_on_uni_stream_data(&driver, 4096U, 0U, &half, 1U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
}

/* A stream that arrives before its session is known has to be answerable: the session is the one its
 * PREFIX named, and the driver is where the prefix was parsed. This is the interface section 4.6's
 * buffering rule needs -- "buffer until it can be associated with an established session" -- because
 * without the ID a caller cannot tell "mine, early" from "not mine" (WT-180). */
void test_a_data_stream_knows_its_session(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t wire[16];
  wt_writer_t w;
  uint64_t session_id = 0U;
  size_t wire_length;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  /* The server has NOT accepted a session yet: no ID is set on the driver, which is exactly the state a
   * stream can arrive in. */
  WT_EXPECT_STATUS("an unknown stream names no session", WT_ERR_CLOSED,
                   wt_http3_driver_data_stream_session_id(&driver, 0U, &session_id));

  /* A peer's unidirectional WebTransport stream: the draft's type 0x54, the session it names, then bytes. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a unidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 1, 8U));
  wt_writer_bytes(&w, "early", 5U);
  wire_length = wt_writer_offset(&w);
  WT_EXPECT_OK("the peer's stream is classified",
               wt_http3_driver_on_uni_stream_data(&driver, 2U, 0U, wire, wire_length, &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as a WebTransport stream", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("with the payload after the prefix", 5U, (uint64_t)payload_length);
  WT_EXPECT_TRUE("and the prefix consumed", consumed > 0U);
  WT_EXPECT_U64("which the driver remembers", 1U,
                (uint64_t)wt_http3_driver_is_data_stream(&driver, 2U));

  /* The ID is the one in the prefix -- NOT the driver's own (there is none), and not zero. */
  WT_EXPECT_OK("and its session is readable",
               wt_http3_driver_data_stream_session_id(&driver, 2U, &session_id));
  WT_EXPECT_U64("as the session the prefix named", 8U, session_id);

  /* A stream that was never seen is CLOSED, which a caller can tell apart from "remembered but unknown". */
  WT_EXPECT_STATUS("a stream the driver never saw names nothing", WT_ERR_CLOSED,
                   wt_http3_driver_data_stream_session_id(&driver, 6U, &session_id));
}

/* F-07: a WebTransport unidirectional prefix split between the TYPE and the SESSION ID. The session ID is part
 * of the prefix, so a frame carrying only the type must be held and NOT classified; the frame that completes
 * the prefix must apply the session check before the endpoint is told the kind, and hand the session only the
 * bytes after the whole prefix. Before the fix the first frame classified the stream WEBTRANSPORT and returned
 * WT_ERR_TRUNCATED, which the frame route turns into a connection close with INTERNAL_ERROR, and the retry then
 * saw a stored WEBTRANSPORT kind and delivered the session ID's bytes as payload with no check at all. */
void test_a_webtransport_uni_prefix_split_after_the_type(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t type[8];
  uint8_t rest[16];
  size_t type_length;
  size_t rest_length;
  uint64_t named = 0U;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 4U);

  type_length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, type, sizeof(type));
  rest_length = wt_quic_varint_encode(4U, rest, sizeof(rest));
  rest[rest_length] = 0xaaU;
  rest[rest_length + 1U] = 0xbbU;
  rest[rest_length + 2U] = 0xccU;
  rest_length += 3U;

  /* The first frame carries the TYPE only: nothing classified, nothing delivered, one entry held. */
  WT_EXPECT_OK("the type alone is held",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, type, type_length, &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("with nothing classified", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN, (int)kind);
  WT_EXPECT_U64("no payload", 0U, (uint64_t)payload_length);
  WT_EXPECT_U64("the type consumed", (uint64_t)type_length, (uint64_t)consumed);
  WT_EXPECT_U64("one stream waiting", 1U, (uint64_t)wt_http3_driver_pending_count(&driver));
  /* The endpoint must not have been told the kind, or a later frame on this stream would skip the prefix. */
  WT_EXPECT_INT("and the stream is not marked WebTransport yet",
                (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN,
                (int)wt_http3_endpoint_stream_kind(&endpoint, 3U));

  /* The second frame completes the prefix (the session ID) and carries payload behind it: only the session
   * ID's one byte comes out of this frame, and the payload starts after the whole prefix. */
  WT_EXPECT_OK("the session ID completes the prefix",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, type_length, rest, rest_length,
                                                  &kind, &payload, &payload_length, &consumed,
                                                  &error));
  WT_EXPECT_INT("classifying the stream", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("with only the session ID taken from this frame", 1U, (uint64_t)consumed);
  WT_EXPECT_U64("leaving the rest as payload", 3U, (uint64_t)payload_length);
  WT_EXPECT_TRUE("starting right after the session ID", payload == rest + 1U);
  if (payload != NULL && payload_length > 0U) {
    WT_EXPECT_U64("and the first payload byte is the payload's", 0xaaU, (uint64_t)payload[0]);
  }
  WT_EXPECT_U64("with nothing left waiting", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
  WT_EXPECT_OK("and the stream is remembered for the session its prefix named",
               wt_http3_driver_data_stream_session_id(&driver, 3U, &named));
  WT_EXPECT_U64("which is this session", 4U, named);

  /* A split prefix naming ANOTHER session: the comparison must happen before classification, so the stream
   * leaves no trace in the endpoint and no payload reaches this session. */
  {
    uint8_t wrong[8];
    size_t wrong_length = wt_quic_varint_encode(12U, wrong, sizeof(wrong));
    wrong[wrong_length] = 0xddU;
    wrong_length += 1U;

    WT_EXPECT_OK("a wrong session's type is held too",
                 wt_http3_driver_on_uni_stream_data(&driver, 7U, 0U, type, type_length, &kind,
                                                    &payload, &payload_length, &consumed, &error));
    WT_EXPECT_STATUS("a stream for another session is refused", WT_ERR_PROTOCOL,
                     wt_http3_driver_on_uni_stream_data(&driver, 7U, type_length, wrong,
                                                        wrong_length, &kind, &payload,
                                                        &payload_length, &consumed, &error));
    WT_EXPECT_U64("with the id error code", WT_HTTP3_ID_ERROR, (uint64_t)error);
    WT_EXPECT_INT("and the endpoint was never told the kind", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN,
                  (int)wt_http3_endpoint_stream_kind(&endpoint, 7U));
    WT_EXPECT_U64("with nothing left waiting", 0U,
                  (uint64_t)wt_http3_driver_pending_count(&driver));
  }

  /* And through the FRAME route, which is where the unfixed code closed the connection with INTERNAL_ERROR:
   * the first frame is held, the second completes the prefix and hands the session exactly the payload. */
  {
    wt_http3_endpoint_t route_endpoint;
    wt_http3_driver_t route_driver;
    wt_http3_driver_sink_t sink;
    session_log_t session;
    wt_quic_frame_t frame;

    memset(&session, 0, sizeof(session));
    memset(&sink, 0, sizeof(sink));
    sink.on_stream_data = record_stream_data;
    sink.context = &session;
    wt_http3_endpoint_init(&route_endpoint, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&route_driver, &route_endpoint);
    wt_http3_driver_set_session_id(&route_driver, 4U);

    memset(&frame, 0, sizeof(frame));
    frame.kind = WT_QUIC_FRAME_KIND_STREAM;
    frame.as.stream.id = 2U; /* a peer-initiated unidirectional stream */
    frame.as.stream.has_length = 1;
    frame.as.stream.offset = 0U;
    frame.as.stream.data = type;
    frame.as.stream.length = type_length;
    WT_EXPECT_OK("the frame route holds the type",
                 wt_http3_driver_on_quic_frame(&route_driver, WT_QUIC_SPACE_APPLICATION, &frame,
                                               &sink, 4096U));
    WT_EXPECT_U64("delivering nothing", 0U, (uint64_t)session.streams);

    frame.as.stream.offset = type_length;
    frame.as.stream.data = rest;
    frame.as.stream.length = rest_length;
    WT_EXPECT_OK("and the session ID completes the prefix",
                 wt_http3_driver_on_quic_frame(&route_driver, WT_QUIC_SPACE_APPLICATION, &frame,
                                               &sink, 4096U));
    WT_EXPECT_U64("delivering the payload once", 1U, (uint64_t)session.streams);
    WT_EXPECT_U64("with no session-ID byte in it", 3U, (uint64_t)session.stream_bytes);
    WT_EXPECT_U64("for the stream it arrived on", 2U, session.last_stream_id);
  }
}
