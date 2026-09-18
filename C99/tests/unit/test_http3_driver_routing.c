#include "test_http3_driver_internal.h"

/* Both logs in one context, because one sink carries all three callbacks: a callback that
 * cast the context to the wrong log would write into the other one, which is exactly the kind
 * of mistake this test would then be unable to see. */
typedef struct route_log {
  frame_log_t frames;
  session_log_t session;
} route_log_t;

static wt_status_t route_frame(void *context, uint64_t stream_id, uint64_t type,
                               const uint8_t *payload, size_t length, int last) {
  return record_frame(&((route_log_t *)context)->frames, stream_id, type, payload, length, last);
}

static wt_status_t route_stream(void *context, uint64_t stream_id, const uint8_t *data,
                                size_t length, int fin) {
  return record_stream_data(&((route_log_t *)context)->session, stream_id, data, length, fin);
}

static wt_status_t route_datagram(void *context, const uint8_t *data, size_t length) {
  return record_datagram(&((route_log_t *)context)->session, data, length);
}

void test_a_connection_frame_is_routed(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  route_log_t log;
  wt_quic_frame_t frame;
  uint8_t prefix[8];
  uint8_t body[16];
  size_t prefix_length;
  size_t i;

  memset(&log, 0, sizeof(log));
  sink.on_frame_payload = route_frame;
  sink.on_stream_data = route_stream;
  sink.on_datagram = route_datagram;
  sink.context = &log;

  /* A server: the peer is the client, so client-initiated stream IDs (low bit clear) are the
   * peer's. */
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  /* The draft's WebTransport stream: the prefix, then session bytes that are NOT HTTP/3
   * log.frames. They go to the session sink, and the frame sink must not see them. */
  prefix_length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, prefix, sizeof(prefix));
  /* The session ID is part of the draft's prefix, so a frame that stops after the type is TRUNCATED rather
   * than a stream whose payload begins with its own session ID. */
  prefix_length +=
      wt_quic_varint_encode(0U, prefix + prefix_length, sizeof(prefix) - prefix_length);
  for (i = 0U; i < sizeof(body); i++)
    body[i] = (uint8_t)(0x10U + i);
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 2U; /* client-initiated unidirectional: low bit clear */
  frame.as.stream.offset = 0U;
  frame.as.stream.has_offset = 0;
  frame.as.stream.fin = 0;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = prefix;
  frame.as.stream.length = prefix_length;
  WT_EXPECT_OK(
      "the prefix frame is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("delivering nothing to the session yet", 0U, (uint64_t)log.session.streams);
  WT_EXPECT_U64("and nothing to the frame sink", 0U, (uint64_t)log.frames.frames);

  frame.as.stream.offset = prefix_length;
  frame.as.stream.has_offset = 1;
  frame.as.stream.data = body;
  frame.as.stream.length = sizeof(body);
  WT_EXPECT_OK(
      "the data frame is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("handing the session its bytes", 1U, (uint64_t)log.session.streams);
  WT_EXPECT_U64("all of them", (uint64_t)sizeof(body), (uint64_t)log.session.stream_bytes);
  WT_EXPECT_U64("for that stream", 2U, log.session.last_stream_id);

  /* The control stream's frames go to the FRAME sink instead: the same shape of frame, a
   * different destination, decided by the stream's type prefix rather than by the caller. */
  {
    uint8_t control[32];
    wt_writer_t cw;
    wt_http3_frame_t settings = wt_http3_frame_make(WT_HTTP3_FRAME_SETTINGS);

    control[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
    cw = wt_writer_init(control + 1U, sizeof(control) - 1U);
    settings.payload = NULL;
    settings.length = 0U;
    WT_EXPECT_OK("a settings frame writes", wt_http3_frame_encode(&cw, &settings));

    frame.kind = WT_QUIC_FRAME_KIND_STREAM;
    frame.as.stream.id = 6U; /* client-initiated unidirectional */
    frame.as.stream.offset = 0U;
    frame.as.stream.has_offset = 0;
    frame.as.stream.fin = 0;
    frame.as.stream.has_length = 1;
    frame.as.stream.data = control;
    frame.as.stream.length = 1U + wt_writer_offset(&cw);
    WT_EXPECT_OK(
        "the control stream's first frame is routed",
        wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
    WT_EXPECT_U64("to the frame sink", 1U, (uint64_t)log.frames.frames);
    WT_EXPECT_U64("as SETTINGS", WT_HTTP3_FRAME_SETTINGS, log.frames.last_type);
    WT_EXPECT_U64("and not to the session", 1U, (uint64_t)log.session.streams);
  }

  /* A datagram is the session's, uninterpreted. */
  frame.kind = WT_QUIC_FRAME_KIND_DATAGRAM;
  frame.as.datagram.data = body;
  frame.as.datagram.length = 4U;
  WT_EXPECT_OK("a datagram is routed", wt_http3_driver_on_quic_frame(
                                           &driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("as one datagram", 1U, (uint64_t)log.session.datagrams);
  WT_EXPECT_U64("of its four bytes", 4U, (uint64_t)log.session.datagram_bytes);

  /* A frame on a stream THIS endpoint opened is not routed at all: the peer's answer belongs
   * to the connection's own stream state. */
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 3U; /* server-initiated: ours, so not routed */
  WT_EXPECT_OK(
      "our own stream's frame is ignored",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("reaching neither sink", 1U, (uint64_t)log.session.streams);

  /* A frame kind this layer has no interest in is ignored rather than refused. */
  frame.kind = WT_QUIC_FRAME_KIND_PING;
  WT_EXPECT_OK(
      "a ping is not ours to route",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
}

/* The bidirectional-stream classifier, on its own: the routing that uses it is a separate step because that is
 * where WT-120's release-build crash lived, and a pure function can be proven in all three configurations
 * first. */
void test_the_bidi_classifier(void) {
  uint8_t wire[16];
  wt_writer_t w;
  size_t length;
  size_t consumed = 0U;
  uint64_t session_id = 0U;
  wt_http3_bidi_start_kind_t kind = WT_HTTP3_BIDI_START_REQUEST;

  /* The draft's bidirectional prefix: `0x41` and the session ID. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a bidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 0, 4U));
  wt_writer_bytes(&w, "body", 4U);
  length = wt_writer_offset(&w);
  WT_EXPECT_OK("and classifies as WebTransport",
               wt_http3_driver_classify_bidi_start(wire, length, &kind, &session_id, &consumed));
  WT_EXPECT_INT("as the WebTransport kind", (int)WT_HTTP3_BIDI_START_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("naming the session", 4U, session_id);
  /* Three bytes: the TYPE `0x41` needs a two-byte varint (65 > 63) and the session id is one byte. This is the
   * MSB-first varint lesson the tracker has recorded several times, and the assertion that caught it here was
   * "consumed is the prefix, not the body". */
  WT_EXPECT_U64("with the prefix's length consumed, not the body's", 3U, (uint64_t)consumed);

  /* An HTTP/3 request stream: a QPACK prefix, which is not the draft's type. */
  {
    uint8_t request[8];
    wt_writer_t rw = wt_writer_init(request, sizeof(request));
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x80U);
    WT_EXPECT_OK("a request stream classifies as a request",
                 wt_http3_driver_classify_bidi_start(request, wt_writer_offset(&rw), &kind,
                                                     &session_id, &consumed));
    WT_EXPECT_INT("as the request kind", (int)WT_HTTP3_BIDI_START_REQUEST, (int)kind);
    WT_EXPECT_U64("with nothing consumed", 0U, (uint64_t)consumed);
  }

  /* A prefix that has not fully arrived is a WAIT on a stream, never a refusal. */
  WT_EXPECT_STATUS("a lone type byte is incomplete", WT_ERR_TRUNCATED,
                   wt_http3_driver_classify_bidi_start(wire, 1U, &kind, &session_id, &consumed));
  /* And nothing at all is simply a stream with no bytes yet: a request stream until proven otherwise. */
  WT_EXPECT_OK("no bytes classify as a request",
               wt_http3_driver_classify_bidi_start(NULL, 0U, &kind, &session_id, &consumed));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_driver_classify_bidi_start(wire, length, NULL, &session_id, &consumed));
}

/* The ROUTING that uses the classifier, which is the step that crashed in the release build when it was first
 * attempted. The classifier is proven on its own (above); this proves that a WebTransport bidirectional stream
 * reaches the SESSION sink with its prefix removed, and that a request-shaped stream does not go there. */
void test_a_bidi_stream_is_routed_by_its_prefix(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  session_log_t session;
  wt_quic_frame_t frame;
  uint8_t wire[64];
  uint8_t request[8];
  wt_writer_t w;
  size_t wire_length;

  memset(&session, 0, sizeof(session));
  memset(&sink, 0, sizeof(sink));
  sink.on_stream_data = record_stream_data;
  sink.context = &session;
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 4U);

  /* The draft's bidirectional prefix and then the session's bytes. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a bidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 0, 4U));
  wt_writer_bytes(&w, "hello", 5U);
  wire_length = wt_writer_offset(&w);

  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 0U; /* a peer-initiated (client) bidirectional stream */
  frame.as.stream.offset = 0U;
  frame.as.stream.fin = 0;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = wire;
  frame.as.stream.length = wire_length;

  WT_EXPECT_OK(
      "a WebTransport stream is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
  WT_EXPECT_U64("the session is handed the bytes", 1U, (uint64_t)session.streams);
  WT_EXPECT_U64("after the prefix, and only those", 5U, (uint64_t)session.stream_bytes);
  WT_EXPECT_U64("for the stream they arrived on", 0U, session.last_stream_id);
  /* And the driver can say which session the stream named, which is what section 4.6's buffering rule asks
   * for when the session is not known yet (WT-180). */
  {
    uint64_t named = 0U;
    WT_EXPECT_OK("the stream's session is readable",
                 wt_http3_driver_data_stream_session_id(&driver, 0U, &named));
    WT_EXPECT_U64("as the one its prefix named", 4U, named);
  }

  /* A stream naming ANOTHER session is refused rather than delivered to this one. */
  {
    wt_http3_driver_t other;
    wt_http3_endpoint_t other_endpoint;
    /* Initialised before the driver is handed the pointer: the driver reads the endpoint's role and walks
     * its request table, so an uninitialised endpoint is undefined behaviour, not a shortcut. */
    wt_http3_endpoint_init(&other_endpoint, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&other, &other_endpoint);
    wt_http3_driver_set_session_id(&other, 12U);
    frame.as.stream.id = 4U;
    WT_EXPECT_STATUS(
        "a stream for another session is refused", WT_ERR_PROTOCOL,
        wt_http3_driver_on_quic_frame(&other, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
    WT_EXPECT_U64("and reaches the session never", 1U, (uint64_t)session.streams);
  }

  /* A request-shaped stream is an HTTP/3 request and does NOT go to the session sink. */
  {
    wt_writer_t rw = wt_writer_init(request, sizeof(request));
    wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x00U);
    wt_writer_bytes(&rw, "x", 1U);
    frame.as.stream.id = 8U;
    frame.as.stream.data = request;
    frame.as.stream.length = wt_writer_offset(&rw);
    (void)wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U);
    WT_EXPECT_U64("a request stream does not reach the session as data", 1U,
                  (uint64_t)session.streams);
    /* And the endpoint tracks it as a request stream, which is what makes it a request rather than nothing. */
    WT_EXPECT_OK("while the endpoint tracks it as a request",
                 wt_http3_endpoint_request_state(&endpoint, 8U, &state));
  }
}

/* A prefix that arrives in PIECES on a bidirectional stream: the held bytes must be assembled, and for a
 * REQUEST they must be REPLAYED -- the request path has to see a stream's first bytes rather than the middle of
 * them. The first implementation skipped the assembly for the continuation frame, because its offset is not
 * zero, and the counter that made the frame path say so is what found it. */
void test_a_bidirectional_prefix_split_across_frames(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  session_log_t session;
  wt_quic_frame_t frame;
  uint8_t wire[64];
  wt_writer_t w;
  size_t wire_length;

  memset(&session, 0, sizeof(session));
  memset(&sink, 0, sizeof(sink));
  sink.on_stream_data = record_stream_data;
  sink.context = &session;
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 4U);

  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a bidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 0, 4U));
  wt_writer_bytes(&w, "split", 5U);
  wire_length = wt_writer_offset(&w);

  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = wire;
  frame.as.stream.length = 1U; /* inside the two-byte type: nothing is decided yet */
  WT_EXPECT_OK(
      "the first piece is held",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
  WT_EXPECT_U64("with nothing delivered", 0U, (uint64_t)session.streams);
  WT_EXPECT_U64("and the stream waiting", 1U, (uint64_t)wt_http3_driver_pending_count(&driver));
  frame.as.stream.offset = 1U;
  frame.as.stream.data = wire + 1;
  frame.as.stream.length = wire_length - 1U;
  WT_EXPECT_OK(
      "the rest completes the prefix",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
  WT_EXPECT_U64("and the session has the payload", 5U, (uint64_t)session.stream_bytes);
  WT_EXPECT_U64("delivered once", 1U, (uint64_t)session.streams);
  WT_EXPECT_U64("with nothing left waiting", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));

  /* A REQUEST split the same way: the held bytes are replayed, so the request path sees the first bytes. */
  {
    wt_http3_driver_t request_driver;
    wt_http3_endpoint_t request_endpoint;
    wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
    uint8_t request[8];
    wt_writer_t rw = wt_writer_init(request, sizeof(request));

    wt_http3_endpoint_init(&request_endpoint, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&request_driver, &request_endpoint);
    wt_writer_u8(&rw, 0x00U); /* a QPACK prefix and then a DATA frame */
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x01U);
    wt_writer_u8(&rw, 0x00U);
    frame.as.stream.id = 4U;
    frame.as.stream.offset = 0U;
    frame.as.stream.data = request;
    frame.as.stream.length = 2U;
    WT_EXPECT_OK("half a request prefix is held",
                 wt_http3_driver_on_quic_frame(&request_driver, WT_QUIC_SPACE_APPLICATION, &frame,
                                               &sink, 4096U));
    frame.as.stream.offset = 2U;
    frame.as.stream.data = request + 2;
    frame.as.stream.length = wt_writer_offset(&rw) - 2U;
    WT_EXPECT_OK("and its rest goes to the request path",
                 wt_http3_driver_on_quic_frame(&request_driver, WT_QUIC_SPACE_APPLICATION, &frame,
                                               &sink, 4096U));
    WT_EXPECT_OK("which tracks the stream",
                 wt_http3_endpoint_request_state(&request_endpoint, 4U, &state));
    WT_EXPECT_TRUE("with the frames it was given applied",
                   state == WT_HTTP3_REQUEST_BODY || state == WT_HTTP3_REQUEST_EXPECT_HEADERS);
    WT_EXPECT_U64("and the session was told nothing", 1U, (uint64_t)session.streams);
  }
}

/* --------------------------------------------------------------- WT-251: a received SETTINGS payload */

/* One STREAM frame, shaped the way a QUIC connection reports it. */
static wt_status_t route_stream_frame(wt_http3_driver_t *driver, const wt_http3_driver_sink_t *sink,
                                      uint64_t stream_id, uint64_t offset, const uint8_t *bytes,
                                      size_t length, int fin) {
  wt_quic_frame_t frame;

  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = stream_id;
  frame.as.stream.offset = offset;
  frame.as.stream.has_offset = offset != 0U ? 1 : 0;
  frame.as.stream.fin = fin;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = bytes;
  frame.as.stream.length = length;
  return wt_http3_driver_on_quic_frame(driver, WT_QUIC_SPACE_APPLICATION, &frame, sink, 4096U);
}

/* A SETTINGS frame's type, length and payload, in `out`. Returns its length. */
static size_t encode_settings_frame(uint8_t *out, size_t capacity, const uint8_t *payload,
                                    size_t payload_length) {
  wt_writer_t w = wt_writer_init(out, capacity);
  wt_http3_frame_t settings = wt_http3_frame_make(WT_HTTP3_FRAME_SETTINGS);

  settings.payload = payload;
  settings.length = payload_length;
  if (wt_http3_frame_encode(&w, &settings) != WT_OK) return 0U;
  return wt_writer_offset(&w);
}

/* WT-251. RFC 9114 section 7.2.4: "The same setting identifier MUST NOT occur more than once in
 * the SETTINGS frame. A receiver MAY treat the presence of duplicate setting identifiers as a
 * connection error of type H3_SETTINGS_ERROR." This build takes that option in
 * `wt_http3_settings_parse`, but until now nothing fed a RECEIVED payload to it: the control
 * machine tracked only a `settings_received` boolean and the payload went straight to the sink
 * unread, so `04 04 08 01 08 01` (SETTINGS, identifier 8 twice) came back WT_OK with
 * H3_NO_ERROR and the sink was handed the frame.
 *
 * The control machine now reassembles the peer's SETTINGS payload across the pieces the
 * connection delivers it in and validates the completed frame with the existing parser, so the
 * duplicate closes the connection with H3_SETTINGS_ERROR. The duplicate is SPLIT across two
 * STREAM frames below, because that is what makes reassembly -- rather than per-piece reading --
 * the property being tested.
 *
 * A second SETTINGS FRAME is a different rule and stays where it was: section 7.2.4 says a
 * second SETTINGS frame on the control stream is H3_FRAME_UNEXPECTED (section 6.2.1 says nothing
 * about a second SETTINGS), and the control machine already returned that. */
void test_a_duplicate_settings_identifier_is_refused(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  frame_log_t frames;
  uint8_t frame_bytes[16];
  uint8_t wire[32];
  size_t frame_length;
  /* Identifier 8 (ENABLE_CONNECT_PROTOCOL) twice, both boolean-legal, so the duplicate is the
   * only rule the payload breaks. */
  static const uint8_t duplicate_payload[] = {0x08U, 0x01U, 0x08U, 0x01U};
  static const uint8_t ok_payload[] = {0x08U, 0x01U};

  memset(&frames, 0, sizeof(frames));
  memset(&sink, 0, sizeof(sink));
  sink.on_frame_payload = record_frame;
  sink.context = &frames;

  /* A valid payload is accepted and still reaches the sink: the new validation must not refuse
   * what the parser has always accepted. */
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wire[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
  frame_length =
      encode_settings_frame(frame_bytes, sizeof(frame_bytes), ok_payload, sizeof(ok_payload));
  WT_EXPECT_TRUE("the valid SETTINGS frame encodes", frame_length > 0U);
  memcpy(wire + 1U, frame_bytes, frame_length);
  WT_EXPECT_OK("a valid SETTINGS payload is accepted",
               route_stream_frame(&driver, &sink, 2U, 0U, wire, 1U + frame_length, 0));
  WT_EXPECT_U64("and reaches the sink", 1U, (uint64_t)frames.frames);
  WT_EXPECT_U64("as SETTINGS", WT_HTTP3_FRAME_SETTINGS, frames.last_type);

  /* The duplicate in one piece: the case the investigation found returning WT_OK. */
  memset(&frames, 0, sizeof(frames));
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wire[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
  frame_length = encode_settings_frame(frame_bytes, sizeof(frame_bytes), duplicate_payload,
                                       sizeof(duplicate_payload));
  memcpy(wire + 1U, frame_bytes, frame_length);
  WT_EXPECT_STATUS("a duplicate identifier is refused", WT_ERR_PROTOCOL,
                   route_stream_frame(&driver, &sink, 2U, 0U, wire, 1U + frame_length, 0));
  WT_EXPECT_U64("with H3_SETTINGS_ERROR", WT_HTTP3_SETTINGS_ERROR,
                (uint64_t)wt_http3_driver_last_error(&driver));
  WT_EXPECT_U64("and the refused frame never reaches the sink", 0U, (uint64_t)frames.frames);

  /* The same duplicate SPLIT: the prefix, the frame header and the first parameter in one STREAM
   * frame, the repeated parameter in the next. A receiver that read each piece on its own would
   * see two legal settings and no duplicate, which is the defect reassembly closes. The frame's
   * first piece is delivered to the sink before the second completes the frame; the refusal
   * follows. */
  memset(&frames, 0, sizeof(frames));
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wire[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
  frame_length = encode_settings_frame(frame_bytes, sizeof(frame_bytes), duplicate_payload,
                                       sizeof(duplicate_payload));
  memcpy(wire + 1U, frame_bytes, frame_length);
  WT_EXPECT_OK("the first half is accepted",
               route_stream_frame(&driver, &sink, 2U, 0U, wire, 1U + 2U + 2U, 0));
  WT_EXPECT_STATUS(
      "the duplicate in the second half is refused", WT_ERR_PROTOCOL,
      route_stream_frame(&driver, &sink, 2U, 1U + 2U + 2U, wire + 1U + 2U + 2U, 2U, 0));
  WT_EXPECT_U64("with H3_SETTINGS_ERROR", WT_HTTP3_SETTINGS_ERROR,
                (uint64_t)wt_http3_driver_last_error(&driver));

  /* A second SETTINGS FRAME is H3_FRAME_UNEXPECTED (RFC 9114 section 7.2.4), which the control
   * machine already enforced; this pins that the duplicate-payload rule did not replace it. */
  memset(&frames, 0, sizeof(frames));
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wire[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
  frame_length =
      encode_settings_frame(frame_bytes, sizeof(frame_bytes), ok_payload, sizeof(ok_payload));
  memcpy(wire + 1U, frame_bytes, frame_length);
  WT_EXPECT_OK("the first SETTINGS is accepted",
               route_stream_frame(&driver, &sink, 2U, 0U, wire, 1U + frame_length, 0));
  WT_EXPECT_STATUS(
      "a second SETTINGS frame is refused", WT_ERR_PROTOCOL,
      route_stream_frame(&driver, &sink, 2U, 1U + frame_length, wire + 1U, frame_length, 0));
  WT_EXPECT_U64("as a frame unexpected", WT_HTTP3_FRAME_UNEXPECTED,
                (uint64_t)wt_http3_driver_last_error(&driver));
}
