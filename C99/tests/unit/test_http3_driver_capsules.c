/* What the driver puts on the wire when a session starts (WT-135).
 *
 * The interop peer's HTTP/3 layer logged nothing after its handshake, while the counters said our packets were
 * read and acknowledged and the keys match -- which leaves the CONTENT of what we send. This is the test that
 * says what that content is: a recording transport, the driver's own start_session, and byte-level assertions on
 * every stream it opens.
 */

#include "wt_test.h"

#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/message.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/connection.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

#include "test_http3_driver_streams_support.h"

static wt_status_t capsule_on_frame(void *context, uint64_t stream_id, uint64_t type,
                                    const uint8_t *payload, size_t length, int last) {
  capsule_sink_t *log = context;

  log->frame_calls++;
  log->frame_type = type;
  if (length > sizeof(log->frame_bytes)) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(log->frame_bytes, payload, length);
  log->frame_length = length;
  log->frame_last = last;
  /* The server's side of the mark, made from INSIDE the HEADERS delivery: that is where a caller learns that the
   * request is a WebTransport CONNECT, and the DATA frame behind it in the same STREAM frame must still reach the
   * session rather than be refused as a frame on a stream nobody has marked yet. */
  if (log->mark_on_headers != 0 && type == (uint64_t)WT_HTTP3_FRAME_HEADERS && last != 0) {
    (void)wt_http3_driver_mark_capsule_stream(log->driver, stream_id, log->mark_headers_pending);
  }
  return WT_OK;
}

static wt_status_t capsule_on_data(void *context, uint64_t stream_id, const uint8_t *data,
                                   size_t length, int fin) {
  capsule_sink_t *log = context;

  (void)stream_id;
  log->data_calls++;
  if (length > sizeof(log->data_bytes)) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(log->data_bytes, data, length);
  log->data_length = length;
  log->data_fin = fin;
  return WT_OK;
}

/* Append one MAX_DATA capsule inside a DATA frame at `buffer + offset`, and report where the frame's payload -- the
 * capsule itself -- sits and how long it is. The reservation the framing needs is taken from `buffer` itself, so
 * the capsule is written once, in the buffer the driver is handed. Returns the new end of the buffer's contents. */
static size_t append_framed_grant(uint8_t *buffer, size_t offset, size_t capacity, uint64_t grant,
                                  size_t *out_payload_offset, size_t *out_payload_length) {
  wt_writer_t w = wt_http3_frame_data_writer(buffer + offset, capacity - offset);
  size_t frame_length = 0U;

  WT_EXPECT_OK("the peer's MAX_DATA capsule encodes", wt_webtransport_max_data_write(&w, grant));
  *out_payload_length = wt_writer_offset(&w);
  WT_EXPECT_OK("and is put inside a DATA frame",
               wt_http3_frame_wrap_data_in_place(buffer + offset, capacity - offset,
                                                 *out_payload_length, &frame_length));
  /* The payload is the last thing in the frame, so this is where the header stopped. */
  *out_payload_offset = offset + frame_length - *out_payload_length;
  return offset + frame_length;
}

static void test_a_connect_streams_capsules_arrive_inside_data_frames(void) {
  static const uint8_t k_headers[] = {0x01U, 0x04U, 's',
                                      'e',   'c',   't'}; /* HEADERS, four bytes of section */
  uint8_t buffer[128];
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_settings_t settings;
  wt_http3_driver_transport_t transport;
  recording_t recording;
  capsule_sink_t log;
  wt_http3_driver_sink_t sink;
  uint64_t request_stream_id = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t capsule_length = 0U;
  size_t capsule_offset = 0U;
  size_t total;

  memset(&recording, 0, sizeof(recording));
  memset(&log, 0, sizeof(log));
  memset(&sink, 0, sizeof(sink));
  memset(&transport, 0, sizeof(transport));
  transport.open_stream = record_open;
  transport.send_stream = record_send;
  transport.send_datagram = record_datagram;
  transport.context = &recording;
  sink.context = &log;
  sink.on_frame_payload = capsule_on_frame;
  sink.on_stream_data = capsule_on_data;
  log.driver = &driver;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the endpoint advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("a session starts",
               wt_http3_driver_start_session(&driver, &transport, &settings, "example.com", "/chat",
                                             0U, 1000U, &request_stream_id, &error));
  /* `start_session` marks the CONNECT stream itself, because the response is the one HTTP/3 frame still to come
   * on it and a caller that had to remember would be a caller that forgets. */
  WT_EXPECT_INT("its CONNECT stream is marked with the response still to come", 0,
                wt_http3_driver_is_capsule_stream(&driver, request_stream_id));

  memcpy(buffer, k_headers, sizeof(k_headers));
  total = append_framed_grant(buffer, sizeof(k_headers), sizeof(buffer), 1024U, &capsule_offset,
                              &capsule_length);

  WT_EXPECT_OK("the response and the capsule in ONE buffer are routed",
               wt_http3_driver_on_stream_bytes(&driver, request_stream_id, buffer, total, 0, 16384U,
                                               &sink, &error));
  WT_EXPECT_U64("the HEADERS frame is framed exactly as before", 1U, (uint64_t)log.frame_calls);
  WT_EXPECT_U64("as a HEADERS frame", 0x01U, log.frame_type);
  WT_EXPECT_BYTES("with the section it carried", k_headers + 2, log.frame_bytes, 4U);
  WT_EXPECT_INT("in one piece", 1, log.frame_last);
  /* The DATA frame is NOT reported as a frame: its payload is the session's byte stream, and a frame sink that saw
   * it as well would be a second reader of the same bytes. */
  WT_EXPECT_U64("and the DATA frame is not a frame to the application", 1U,
                (uint64_t)log.frame_calls);
  WT_EXPECT_U64("while its payload reaches the session", 1U, (uint64_t)log.data_calls);
  WT_EXPECT_U64("as the capsule", (uint64_t)capsule_length, (uint64_t)log.data_length);
  WT_EXPECT_BYTES("byte for byte", buffer + capsule_offset, log.data_bytes, capsule_length);
  WT_EXPECT_INT("with no end of stream", 0, log.data_fin);
  WT_EXPECT_INT("and the stream carries capsules from here", 1,
                wt_http3_driver_is_capsule_stream(&driver, request_stream_id));

  /* What the sink was handed is a real capsule, not a coincidence of framing: it decodes, and its value is the
   * limit the peer granted. */
  {
    wt_cursor_t cursor = wt_cursor_init(log.data_bytes, log.data_length);
    wt_webtransport_capsule_t capsule;
    uint64_t maximum = 0U;

    memset(&capsule, 0, sizeof(capsule));
    WT_EXPECT_OK("the delivered bytes decode as a capsule",
                 wt_webtransport_capsule_decode(&cursor, log.data_length, &capsule, &error));
    WT_EXPECT_U64("of type MAX_DATA", WT_CAPSULE_MAX_DATA, capsule.type);
    WT_EXPECT_OK("whose value parses", wt_webtransport_max_data_parse(&capsule, &maximum, &error));
    WT_EXPECT_U64("as the limit the peer granted", 1024U, maximum);
  }

  /* A second DATA frame is a second delivery. Where one frame ends and the next begins is the SENDER's to choose:
   * two capsules may share one payload just as one capsule may span two, which is why the session does its own
   * byte-keeping rather than reading one capsule per frame. */
  log.data_calls = 0U;
  total = append_framed_grant(buffer, 0U, sizeof(buffer), 4096U, &capsule_offset, &capsule_length);
  WT_EXPECT_OK("a second DATA frame is routed",
               wt_http3_driver_on_stream_bytes(&driver, request_stream_id, buffer, total, 0, 16384U,
                                               &sink, &error));
  WT_EXPECT_U64("and delivered", 1U, (uint64_t)log.data_calls);
  WT_EXPECT_U64("as its own capsule", (uint64_t)capsule_length, (uint64_t)log.data_length);
  WT_EXPECT_BYTES("byte for byte", buffer + capsule_offset, log.data_bytes, capsule_length);

  /* And the stream's end is the session's event too, with no frame left in progress to call it truncated. */
  WT_EXPECT_OK("the CONNECT stream ends",
               wt_http3_driver_on_stream_bytes(&driver, request_stream_id, NULL, 0U, 1, 16384U,
                                               &sink, &error));
  WT_EXPECT_U64("reported as the session's own end", 2U, (uint64_t)log.data_calls);
  WT_EXPECT_U64("with nothing in it", 0U, (uint64_t)log.data_length);
  WT_EXPECT_INT("and the peer's end of stream", 1, log.data_fin);
}

/* The form that hid the defect (WT-249): a capsule written RAW is the header of an UNKNOWN frame type -- a capsule's
 * type is not one RFC 9114 registers -- so section 9 requires the driver to IGNORE it rather than refuse it. The
 * driver has to tolerate that, because a peer written before this fix sends it; and the session must NOT be told a
 * capsule arrived, which is exactly why the raw form looked interoperable for so long. */
static void test_a_raw_capsule_is_ignored_rather_than_read(void) {
  static const uint8_t k_headers[] = {0x01U, 0x04U, 's', 'e', 'c', 't'};
  uint8_t buffer[128];
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_settings_t settings;
  wt_http3_driver_transport_t transport;
  recording_t recording;
  capsule_sink_t log;
  wt_http3_driver_sink_t sink;
  wt_writer_t w;
  uint64_t request_stream_id = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t total;

  memset(&recording, 0, sizeof(recording));
  memset(&log, 0, sizeof(log));
  memset(&sink, 0, sizeof(sink));
  memset(&transport, 0, sizeof(transport));
  transport.open_stream = record_open;
  transport.send_stream = record_send;
  transport.send_datagram = record_datagram;
  transport.context = &recording;
  sink.context = &log;
  sink.on_frame_payload = capsule_on_frame;
  sink.on_stream_data = capsule_on_data;
  log.driver = &driver;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the endpoint advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("a session starts",
               wt_http3_driver_start_session(&driver, &transport, &settings, "example.com", "/chat",
                                             0U, 1000U, &request_stream_id, &error));

  memcpy(buffer, k_headers, sizeof(k_headers));
  w = wt_writer_init(buffer + sizeof(k_headers), sizeof(buffer) - sizeof(k_headers));
  WT_EXPECT_OK("the peer's MAX_DATA capsule encodes", wt_webtransport_max_data_write(&w, 1024U));
  total = sizeof(k_headers) + wt_writer_offset(&w);

  WT_EXPECT_OK("the response and a RAW capsule in ONE buffer are routed",
               wt_http3_driver_on_stream_bytes(&driver, request_stream_id, buffer, total, 0, 16384U,
                                               &sink, &error));
  WT_EXPECT_U64("the HEADERS frame is framed", 1U, (uint64_t)log.frame_calls);
  /* Not one more frame, and no capsule: section 4.4 makes a KNOWN non-DATA frame on a CONNECT stream an error and
   * section 9 makes an UNKNOWN one nothing at all, and a capsule's type is unknown. */
  WT_EXPECT_U64("the raw capsule is not a frame to the application", 1U, (uint64_t)log.frame_calls);
  WT_EXPECT_U64("and not a capsule to the session either", 0U, (uint64_t)log.data_calls);
  WT_EXPECT_INT("on a stream the driver does treat as a capsule stream", 1,
                wt_http3_driver_is_capsule_stream(&driver, request_stream_id));
}

/* RFC 9114 section 4.4, the other half: a KNOWN frame type other than DATA on a CONNECT stream is "a connection
 * error of type H3_FRAME_UNEXPECTED", while an unknown type is ignored as section 9 requires everywhere. */
static void test_a_known_frame_other_than_data_is_refused_on_a_connect_stream(void) {
  static const uint8_t k_response[] = {0x01U, 0x04U, 's', 'e', 'c', 't'};
  static const uint8_t k_goaway[] = {0x07U, 0x01U, 0x04U}; /* GOAWAY, one byte of payload */
  static const uint8_t k_unknown[] = {0x21U, 0x01U,
                                      0x00U}; /* an exerciser type: reserved, and ignored */
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_settings_t settings;
  wt_http3_driver_transport_t transport;
  recording_t recording;
  capsule_sink_t log;
  wt_http3_driver_sink_t sink;
  uint64_t request_stream_id = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  memset(&recording, 0, sizeof(recording));
  memset(&log, 0, sizeof(log));
  memset(&sink, 0, sizeof(sink));
  memset(&transport, 0, sizeof(transport));
  transport.open_stream = record_open;
  transport.send_stream = record_send;
  transport.send_datagram = record_datagram;
  transport.context = &recording;
  sink.context = &log;
  sink.on_frame_payload = capsule_on_frame;
  sink.on_stream_data = capsule_on_data;
  log.driver = &driver;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the endpoint advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("a session starts",
               wt_http3_driver_start_session(&driver, &transport, &settings, "example.com", "/chat",
                                             0U, 1000U, &request_stream_id, &error));

  /* The response's HEADERS settles the mark, so everything after it is the capsule stream's. */
  WT_EXPECT_OK("the response is framed",
               wt_http3_driver_on_stream_bytes(&driver, request_stream_id, k_response,
                                               sizeof(k_response), 0, 16384U, &sink, &error));
  WT_EXPECT_INT("and the stream carries capsules from here", 1,
                wt_http3_driver_is_capsule_stream(&driver, request_stream_id));
  log.frame_calls = 0U;
  log.data_calls = 0U;

  /* The tolerant half first: a type nobody has defined the meaning of is ignored, which is section 9 and is what
   * 0x1f * N + 0x21 exists to exercise. It must also not be handed to the frame sink: on a capsule stream the DATA
   * payload is the session's and everything else is this layer's. */
  WT_EXPECT_OK("an unknown frame type is ignored",
               wt_http3_driver_on_stream_bytes(&driver, request_stream_id, k_unknown,
                                               sizeof(k_unknown), 0, 16384U, &sink, &error));
  WT_EXPECT_U64("with no capsule for the session", 0U, (uint64_t)log.data_calls);
  WT_EXPECT_U64("and no frame reported", 0U, (uint64_t)log.frame_calls);

  /* And the refusing half, LAST: a refusal is the end of the connection the caller is reading from, so the frame
   * state it leaves behind is not something a later frame on the same stream should be measured through. */
  WT_EXPECT_STATUS("a GOAWAY on a CONNECT stream is refused", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_stream_bytes(&driver, request_stream_id, k_goaway,
                                                   sizeof(k_goaway), 0, 16384U, &sink, &error));
  WT_EXPECT_U64("as H3_FRAME_UNEXPECTED", (uint64_t)WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
  WT_EXPECT_U64("and nothing reached the session", 0U, (uint64_t)log.data_calls);
  WT_EXPECT_U64("and nothing reached the frame sink either", 0U, (uint64_t)log.frame_calls);
}

/* The SERVER's half: the mark is made while the request's HEADERS is being delivered, and a DATA frame behind it in
 * the same STREAM frame still has to reach the session (WT-164). */
static void test_a_server_marks_the_connect_stream_as_it_accepts_it(void) {
  static const uint8_t k_headers[] = {0x01U, 0x04U, 's', 'e', 'c', 't'};
  uint8_t buffer[128];
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  capsule_sink_t log;
  wt_http3_driver_sink_t sink;
  wt_quic_frame_t frame;
  size_t capsule_length = 0U;
  size_t capsule_offset = 0U;
  size_t total;
  size_t first_total;

  memset(&log, 0, sizeof(log));
  memset(&sink, 0, sizeof(sink));
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 0U);
  sink.context = &log;
  sink.on_frame_payload = capsule_on_frame;
  sink.on_stream_data = capsule_on_data;
  log.driver = &driver;
  log.mark_on_headers = 1;
  log.mark_headers_pending = 0;

  memcpy(buffer, k_headers, sizeof(k_headers));
  total = append_framed_grant(buffer, sizeof(k_headers), sizeof(buffer), 4096U, &capsule_offset,
                              &capsule_length);
  first_total = total;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = 0U; /* the peer's CONNECT stream */
  frame.as.stream.offset = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = buffer;
  frame.as.stream.length = total;
  frame.as.stream.fin = 0;
  WT_EXPECT_OK(
      "the request and the capsule in one STREAM frame are routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("the request's HEADERS is framed", 1U, (uint64_t)log.frame_calls);
  WT_EXPECT_U64("and the capsule reaches the session", 1U, (uint64_t)log.data_calls);
  WT_EXPECT_U64("whole", (uint64_t)capsule_length, (uint64_t)log.data_length);
  WT_EXPECT_BYTES("byte for byte", buffer + capsule_offset, log.data_bytes, capsule_length);
  WT_EXPECT_INT("with the stream marked from inside that delivery", 1,
                wt_http3_driver_is_capsule_stream(&driver, 0U));

  /* The NEXT STREAM frame on the stream is a DATA frame from its first byte. */
  log.frame_calls = 0U;
  log.data_calls = 0U;
  total = append_framed_grant(buffer, 0U, sizeof(buffer), 8192U, &capsule_offset, &capsule_length);
  frame.as.stream.offset = first_total;
  frame.as.stream.data = buffer;
  frame.as.stream.length = total;
  frame.as.stream.fin = 0;
  WT_EXPECT_OK(
      "the second frame is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("with nothing framed at all", 0U, (uint64_t)log.frame_calls);
  WT_EXPECT_U64("and the capsule delivered", 1U, (uint64_t)log.data_calls);
  WT_EXPECT_BYTES("byte for byte", buffer + capsule_offset, log.data_bytes, capsule_length);

  /* The stream's end is its own delivery, after the frame that carried the last capsule: a DATA frame's payload and
   * the stream's end are two events, and only the session knows whether the pair left it mid-capsule. */
  frame.as.stream.offset = first_total + total;
  frame.as.stream.data = NULL;
  frame.as.stream.length = 0U;
  frame.as.stream.fin = 1;
  WT_EXPECT_OK(
      "the stream's end is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("as the session's own end", 2U, (uint64_t)log.data_calls);
  WT_EXPECT_U64("with nothing in it", 0U, (uint64_t)log.data_length);
  WT_EXPECT_INT("and the peer's end of stream", 1, log.data_fin);
}

/* The `:protocol` token on the wire is this endpoint's CHOICE, not a constant (F-02b).
 *
 * Draft-ietf-webtrans-http3-16 section 3.2 names `webtransport-h3`, so that is what the driver must send when
 * nothing says otherwise -- a zeroed driver, since the draft-16 selection is the enum's zero. The pre-draft
 * `webtransport` is what a peer that predates the rename accepts, and before this selection existed the client
 * could not put it on the wire at all. The assertion is on the DECODED request rather than on the field this code
 * set, because the bytes a peer reads are the evidence. */

/* The request is the fourth stream a session start opens -- control, encoder, decoder, request. */
static void decode_recorded_request(const recording_t *recording, wt_http3_message_t *out) {
  wt_cursor_t cursor = wt_cursor_init(recording->streams[3].bytes, recording->streams[3].length);
  uint8_t scratch[256];
  uint64_t frame_type = 0U;
  uint64_t frame_length = 0U;
  const uint8_t *payload = NULL;
  size_t available = 0U;
  wt_http3_error_t decode_error = WT_HTTP3_NO_ERROR;

  memset(out, 0, sizeof(*out));
  WT_EXPECT_OK("the request's frame header reads", wt_quic_varint_decode(&cursor, &frame_type));
  WT_EXPECT_U64("as a HEADERS frame", 0x01U, frame_type);
  WT_EXPECT_OK("with a length", wt_quic_varint_decode(&cursor, &frame_length));
  payload = wt_cursor_rest(&cursor, &available);
  WT_EXPECT_U64("that matches what follows it", (uint64_t)available, frame_length);
  WT_EXPECT_OK("and the field section decodes",
               wt_http3_message_decode(out, WT_HTTP3_HEADER_REQUEST, payload, (size_t)frame_length,
                                       NULL, 0U, 0U, scratch, sizeof(scratch), &decode_error));
}

static void init_recorded_session(wt_http3_driver_t *driver, wt_http3_endpoint_t *endpoint,
                                  wt_http3_driver_transport_t *transport, recording_t *recording) {
  memset(recording, 0, sizeof(*recording));
  memset(transport, 0, sizeof(*transport));
  transport->open_stream = record_open;
  transport->send_stream = record_send;
  transport->send_datagram = record_datagram;
  transport->context = recording;

  wt_http3_endpoint_init(endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(driver, endpoint);
}

static void start_recorded_session(wt_http3_driver_t *driver,
                                   wt_http3_driver_transport_t *transport, recording_t *recording) {
  wt_http3_settings_t settings;
  uint64_t request_stream_id = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the endpoint advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("a session starts",
               wt_http3_driver_start_session(driver, transport, &settings, "example.com", "/chat",
                                             0U, 1000U, &request_stream_id, &error));
  WT_EXPECT_U64("four streams are opened", 4U, (uint64_t)recording->count);
}

static void test_the_upgrade_token_the_client_sends(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_transport_t transport;
  recording_t recording;
  wt_http3_message_t message;

  /* The default, with no setter call: this is what `wt_http3_driver_init` alone leaves in place, and the assert
   * on the field BEFORE the session starts is half the evidence -- the other half is the bytes below. */
  init_recorded_session(&driver, &endpoint, &transport, &recording);
  WT_EXPECT_INT("a fresh driver holds the draft-16 selection",
                (int)WT_WEBTRANSPORT_UPGRADE_TOKEN_DRAFT16, (int)driver.upgrade_token);
  start_recorded_session(&driver, &transport, &recording);
  decode_recorded_request(&recording, &message);
  WT_EXPECT_U64("so the CONNECT is fifteen bytes of token", 15U, (uint64_t)message.protocol_length);
  WT_EXPECT_BYTES("which is webtransport-h3", (const uint8_t *)"webtransport-h3", message.protocol,
                  strlen("webtransport-h3"));
  WT_EXPECT_TRUE("with the hyphen that the pre-draft token does not have",
                 message.protocol[12] == '-');

  /* The legacy selection: the token a peer that predates the rename accepts, which before F-02b could not be
   * sent at all. The LENGTH is asserted too, because "webtransport" is a prefix of "webtransport-h3" and a
   * twelve-byte comparison of the draft-16 token would pass a byte check while sending the wrong token. */
  init_recorded_session(&driver, &endpoint, &transport, &recording);
  wt_http3_driver_set_upgrade_token(&driver, WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY);
  WT_EXPECT_INT("the setter records the legacy selection",
                (int)WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY, (int)driver.upgrade_token);
  start_recorded_session(&driver, &transport, &recording);
  decode_recorded_request(&recording, &message);
  WT_EXPECT_U64("so the CONNECT is twelve bytes of token", 12U, (uint64_t)message.protocol_length);
  WT_EXPECT_BYTES("which is webtransport", (const uint8_t *)"webtransport", message.protocol,
                  strlen("webtransport"));
  WT_EXPECT_TRUE("and the two tokens are different strings",
                 strcmp(WT_WEBTRANSPORT_PROTOCOL_TOKEN, WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY) !=
                     0);
}

int main(void) {
  test_a_connect_streams_capsules_arrive_inside_data_frames();
  test_a_raw_capsule_is_ignored_rather_than_read();
  test_a_known_frame_other_than_data_is_refused_on_a_connect_stream();
  test_a_server_marks_the_connect_stream_as_it_accepts_it();
  test_the_upgrade_token_the_client_sends();
  WT_TEST_MAIN_END("test_http3_driver_capsules");
}
