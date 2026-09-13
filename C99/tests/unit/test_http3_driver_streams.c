/* What the driver puts on the wire when a session starts (WT-135).
 *
 * The interop peer's HTTP/3 layer logged nothing after its handshake, while the counters said our packets were
 * read and acknowledged and the keys match -- which leaves the CONTENT of what we send. This is the test that
 * says what that content is: a recording transport, the driver's own start_session, and byte-level assertions on
 * every stream it opens.
 */

#include "wt_test.h"

#include <string.h>

#include "webtransport/http3/driver.h"
#include "webtransport/cursor.h"
#include "webtransport/http3/message.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

#define RECORDED_STREAMS 8U
#define RECORDED_BYTES 512U

typedef struct recording {
  struct {
    int bidirectional;
    int opened;
    uint8_t bytes[RECORDED_BYTES];
    size_t length;
  } streams[RECORDED_STREAMS];
  size_t count;
  size_t datagrams;
} recording_t;

static wt_status_t record_open(void *context, int bidirectional, uint64_t *out_stream_id, uint64_t now) {
  recording_t *recording = context;
  (void)now;
  if (recording->count >= RECORDED_STREAMS) return WT_ERR_LIMIT;
  recording->streams[recording->count].bidirectional = bidirectional;
  recording->streams[recording->count].opened = 1;
  recording->streams[recording->count].length = 0U;
  *out_stream_id = (uint64_t)recording->count;
  recording->count++;
  return WT_OK;
}

static wt_status_t record_send(void *context, uint64_t stream_id, const uint8_t *data, size_t length, int fin,
                               uint64_t now) {
  recording_t *recording = context;
  (void)fin;
  (void)now;
  if (stream_id >= recording->count) return WT_ERR_INVALID_ARGUMENT;
  if (recording->streams[stream_id].length + length > RECORDED_BYTES) return WT_ERR_LIMIT;
  memcpy(recording->streams[stream_id].bytes + recording->streams[stream_id].length, data, length);
  recording->streams[stream_id].length += length;
  return WT_OK;
}

static wt_status_t record_datagram(void *context, const uint8_t *data, size_t length) {
  recording_t *recording = context;
  (void)data;
  (void)length;
  recording->datagrams++;
  return WT_OK;
}

static void test_the_streams_a_session_start_opens(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_settings_t settings;
  wt_http3_driver_transport_t transport;
  recording_t recording;
  uint64_t request_stream_id = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t i;

  memset(&recording, 0, sizeof(recording));
  memset(&transport, 0, sizeof(transport));
  transport.open_stream = record_open;
  transport.send_stream = record_send;
  transport.send_datagram = record_datagram;
  transport.context = &recording;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the endpoint advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));

  WT_EXPECT_OK("a session starts",
               wt_http3_driver_start_session(&driver, &transport, &settings, "example.com", "/chat", 0U, 1000U,
                                             &request_stream_id, &error));
  /* The control stream, the two QPACK streams and the request. */
  WT_EXPECT_U64("four streams are opened", 4U, (uint64_t)recording.count);

  /* RFC 9114 section 6: the control stream's type is 0x00 and its FIRST frame is SETTINGS (0x04). */
  WT_EXPECT_TRUE("the control stream is unidirectional", recording.streams[0].bidirectional == 0);
  WT_EXPECT_TRUE("and starts with the control stream type",
                 recording.streams[0].length >= 2U && recording.streams[0].bytes[0] == 0x00U);
  WT_EXPECT_U64("whose first frame is SETTINGS", 0x04U, (uint64_t)recording.streams[0].bytes[1]);

  /* The SETTINGS payload itself, which was the one part of our own output still unread. Asserted as BYTES
   * rather than through a parse: the payload is the identifier 0x2c7cf000 in QUIC's four-byte varint form
   * (0xac 0x7c 0xf0 0x00, the top two bits saying "four bytes") followed by the value 1 -- and my first attempt
   * at this read the stream with a cursor loop that found nothing, which is the third time in this interop work
   * that a hand-written parse was the thing at fault. The bytes are what the peer sees. */
  WT_EXPECT_U64("the control stream is type + SETTINGS + length + payload", 8U,
                (uint64_t)recording.streams[0].length);
  WT_EXPECT_U64("the SETTINGS payload is five bytes long", 0x05U,
                (uint64_t)recording.streams[0].bytes[2]);
  WT_EXPECT_TRUE("and it advertises WT_ENABLED (0x2c7cf000) with the value 1",
                 recording.streams[0].bytes[3] == 0xacU && recording.streams[0].bytes[4] == 0x7cU &&
                     recording.streams[0].bytes[5] == 0xf0U && recording.streams[0].bytes[6] == 0x00U &&
                     recording.streams[0].bytes[7] == 0x01U);

  /* The QPACK streams: 0x02 is the encoder's, 0x03 the decoder's, and their prefixes are all they carry. */
  WT_EXPECT_TRUE("the QPACK encoder stream is one byte of type",
                 recording.streams[1].length == 1U && recording.streams[1].bytes[0] == 0x02U);
  WT_EXPECT_TRUE("and the decoder stream the other",
                 recording.streams[2].length == 1U && recording.streams[2].bytes[0] == 0x03U);

  /* The request: a BIDIRECTIONAL stream whose first frame is HEADERS (0x01). */
  WT_EXPECT_TRUE("the request stream is bidirectional", recording.streams[3].bidirectional != 0);
  WT_EXPECT_TRUE("and its first frame is HEADERS",
                 recording.streams[3].length >= 2U && recording.streams[3].bytes[0] == 0x01U);

  /* And the CONTENT of the request's HEADERS frame, decoded with this tree's own QPACK decoder: the question the
   * interop peer left open is whether the section says what a WebTransport CONNECT must say. */
  {
    wt_cursor_t cursor = wt_cursor_init(recording.streams[3].bytes, recording.streams[3].length);
    wt_http3_message_t message;
    uint8_t scratch[256];
    uint64_t frame_type = 0U;
    uint64_t frame_length = 0U;
    const uint8_t *payload = NULL;
    size_t available = 0U;
    wt_http3_error_t decode_error = WT_HTTP3_NO_ERROR;

    memset(&message, 0, sizeof(message));
    WT_EXPECT_OK("the request's frame header reads", wt_quic_varint_decode(&cursor, &frame_type));
    WT_EXPECT_U64("as a HEADERS frame", 0x01U, frame_type);
    WT_EXPECT_OK("with a length", wt_quic_varint_decode(&cursor, &frame_length));
    payload = wt_cursor_rest(&cursor, &available);
    WT_EXPECT_U64("that matches what follows it", (uint64_t)available, frame_length);
    WT_EXPECT_OK("and the field section decodes",
                 wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, payload, (size_t)frame_length, NULL,
                                         0U, 0U, scratch, sizeof(scratch), &decode_error));
    WT_EXPECT_BYTES("into a CONNECT", (const uint8_t *)"CONNECT", message.method, 7U);
    WT_EXPECT_BYTES("for the WebTransport protocol", (const uint8_t *)"webtransport", message.protocol, 12U);
    WT_EXPECT_BYTES("at the path asked for", (const uint8_t *)"/chat", message.path, 5U);
    WT_EXPECT_BYTES("for the authority asked for", (const uint8_t *)"example.com", message.authority, 11U);
  }

  /* The stream the driver reported is the one it opened for the request. */
  WT_EXPECT_U64("and the driver names the request's stream", 3U, request_stream_id);
  for (i = 0U; i < recording.count; i++) {
    WT_EXPECT_TRUE("every opened stream carried something", recording.streams[i].length > 0U);
  }
}

/* The prefix belongs to the stream's INITIATOR, and to nobody else (draft-16 sections 4.2 and 4.3). A data
 * stream this endpoint opens carries the signal value and the session ID in its first bytes, so the peer's bytes
 * on the SAME stream are payload -- there is no second prefix. Reading them as one is exactly what the interop
 * peer's echo tripped over: `hello-interop`'s first byte was read as a signal value, the classification refused
 * it, and the refusal closed the connection with INTERNAL_ERROR while the tool went on reporting success
 * (WT-135). The other half of the rule is asserted too: on a stream this endpoint did NOT open the bytes ARE a
 * prefix, and payload sent there is not delivered as this session's payload. */

typedef struct data_stream_fake {
  int opened;
  int opened_bidirectional;
  uint64_t stream_id;
  uint8_t sent[64];
  size_t sent_length;
  int sent_fin;
} data_stream_fake_t;

typedef struct data_stream_sink {
  unsigned calls;
  uint64_t stream_id;
  uint8_t bytes[64];
  size_t length;
  int fin;
} data_stream_sink_t;

static wt_status_t data_stream_open(void *context, int bidirectional, uint64_t *out_stream_id, uint64_t now) {
  data_stream_fake_t *fake = context;
  (void)now;
  if (fake->opened != 0) return WT_ERR_STATE;
  fake->opened = 1;
  fake->opened_bidirectional = bidirectional;
  /* RFC 9000 section 2.1: the low bit says who initiated the stream (clear for this endpoint), the next says
   * the direction. */
  fake->stream_id = bidirectional ? 0U : 2U;
  *out_stream_id = fake->stream_id;
  return WT_OK;
}

static wt_status_t data_stream_send(void *context, uint64_t stream_id, const uint8_t *data, size_t length,
                                    int fin, uint64_t now) {
  data_stream_fake_t *fake = context;
  (void)now;
  if (stream_id != fake->stream_id) return WT_ERR_INVALID_ARGUMENT;
  if (fake->sent_length + length > sizeof(fake->sent)) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(fake->sent + fake->sent_length, data, length);
  fake->sent_length += length;
  fake->sent_fin = fin;
  return WT_OK;
}

static wt_status_t data_stream_on_data(void *context, uint64_t stream_id, const uint8_t *data, size_t length,
                                       int fin) {
  data_stream_sink_t *sink = context;
  sink->calls++;
  sink->stream_id = stream_id;
  if (length > sizeof(sink->bytes)) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(sink->bytes, data, length);
  sink->length = length;
  sink->fin = fin;
  return WT_OK;
}

static void test_a_data_stream_this_endpoint_opened(void) {
  static const uint8_t k_message[] = {'h', 'e', 'l', 'l', 'o'};
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_transport_t transport;
  data_stream_fake_t fake;
  data_stream_sink_t sink_log;
  wt_http3_driver_sink_t sink;
  uint64_t stream_id = 0U;
  wt_quic_frame_t frame;
  uint8_t prefix[4];
  size_t prefix_length;

  memset(&fake, 0, sizeof(fake));
  memset(&sink_log, 0, sizeof(sink_log));
  memset(&sink, 0, sizeof(sink));
  memset(&transport, 0, sizeof(transport));
  transport.open_stream = data_stream_open;
  transport.send_stream = data_stream_send;
  transport.context = &fake;
  sink.context = &sink_log;
  sink.on_stream_data = data_stream_on_data;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  /* The session is the CONNECT stream's ID. The app path that learns it is
   * `wt_http3_driver_start_session`; here it is set directly because no session is started. */
  wt_http3_driver_set_session_id(&driver, 0U);

  /* The signal value as QUIC's own varint encoding, which is NOT one byte: 0x41 is above the single-byte range,
   * so the wire form is `40 41` and the session ID follows it. Written here with the encoder rather than by hand,
   * because a hand-written expectation is what got this wrong the first time. */
  prefix_length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_BIDI, prefix, sizeof(prefix));
  prefix_length += wt_quic_varint_encode(0U, prefix + prefix_length, sizeof(prefix) - prefix_length);

  WT_EXPECT_OK("a data stream opens and the message goes out",
               wt_http3_driver_open_data_stream(&driver, &transport, 0, k_message, sizeof(k_message), 1,
                                                1000U, &stream_id));
  WT_EXPECT_INT("as a bidirectional one", 1, fake.opened_bidirectional);
  WT_EXPECT_U64("on the stream the transport gave", fake.stream_id, stream_id);
  WT_EXPECT_U64("carrying the prefix and then the message", (uint64_t)(prefix_length + sizeof(k_message)),
                (uint64_t)fake.sent_length);
  WT_EXPECT_BYTES("whose first bytes are the signal value and the session", prefix, fake.sent, prefix_length);
  WT_EXPECT_BYTES("and whose rest is the message", k_message, fake.sent + prefix_length, sizeof(k_message));
  WT_EXPECT_INT("and the message finishes the stream", 1, fake.sent_fin);
  WT_EXPECT_INT("and the stream is remembered as this endpoint's", 1,
                wt_http3_driver_is_data_stream(&driver, stream_id));

  /* The ANSWER on the same stream: payload with NO prefix, which is what a responder sends. */
  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = stream_id;
  frame.as.stream.offset = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = k_message;
  frame.as.stream.length = sizeof(k_message);
  frame.as.stream.fin = 1;
  WT_EXPECT_OK("the answer is routed",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("straight to the session sink", 1U, (uint64_t)sink_log.calls);
  WT_EXPECT_U64("for the stream it arrived on", stream_id, sink_log.stream_id);
  WT_EXPECT_BYTES("as the payload, unchanged", k_message, sink_log.bytes, sizeof(k_message));
  WT_EXPECT_INT("with the peer's end of stream", 1, sink_log.fin);

  /* And the other half of the rule: a stream this endpoint did NOT open is where a prefix belongs, so the same
   * bytes there are an HTTP/3 request stream's and not this session's payload. */
  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 4U; /* client-initiated and bidirectional, and NOT one this endpoint opened */
  frame.as.stream.offset = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = k_message;
  frame.as.stream.length = sizeof(k_message);
  (void)wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U);
  WT_EXPECT_U64("an unowned bidirectional stream is not this session's payload", 1U,
                (uint64_t)sink_log.calls);
}

/* A peer that sends the prefix and the message in SEPARATE STREAM frames (WT-156).
 *
 * This is what aioquic's client does, and what turned `wt-server-c99`'s first session with a third-party client into
 * `"closeCause":"truncated"`: the prefix was classified correctly and then FORGOTTEN, so the next frame on the same
 * stream took the request-stream path and its bytes were parsed as HTTP/3 frames -- a frame type read out of the
 * message itself, waiting for a length that never came, and a connection closed at FIN. The tree's own client puts
 * the prefix and the message in one frame, which is exactly why every test in it passed. */
static void test_a_data_stream_the_peer_splits_across_frames(void) {
  static const uint8_t k_prefix[] = {0x40U, 0x41U, 0x00U}; /* the bidirectional signal value and session 0 */
  static const uint8_t k_message[] = {'h', 'e', 'l', 'l', 'o'};
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  data_stream_sink_t sink_log;
  wt_http3_driver_sink_t sink;
  wt_quic_frame_t frame;

  memset(&sink_log, 0, sizeof(sink_log));
  memset(&sink, 0, sizeof(sink));
  sink.context = &sink_log;
  sink.on_stream_data = data_stream_on_data;

  /* A SERVER: the peer initiates the stream, and this endpoint is the one that must classify it. */
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 0U);

  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 4U; /* the peer's first data stream, after its request on stream 0 */
  frame.as.stream.offset = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = k_prefix;
  frame.as.stream.length = sizeof(k_prefix);
  frame.as.stream.fin = 0;
  WT_EXPECT_OK("the prefix frame is routed",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("delivering nothing yet, because the prefix carries no payload", 0U, (uint64_t)sink_log.calls);
  WT_EXPECT_INT("but the stream is remembered as a data stream", 1,
                wt_http3_driver_is_data_stream(&driver, 4U));

  /* The message, in the NEXT frame, at a non-zero offset: this is the frame that used to be mis-routed. */
  frame.as.stream.offset = sizeof(k_prefix);
  frame.as.stream.data = k_message;
  frame.as.stream.length = sizeof(k_message);
  frame.as.stream.fin = 1;
  WT_EXPECT_OK("the message frame is routed",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("straight to the session sink", 1U, (uint64_t)sink_log.calls);
  WT_EXPECT_BYTES("as the payload, unchanged", k_message, sink_log.bytes, sizeof(k_message));
  WT_EXPECT_INT("with the peer's end of stream", 1, sink_log.fin);
}

int main(void) {
  test_the_streams_a_session_start_opens();
  test_a_data_stream_this_endpoint_opened();
  test_a_data_stream_the_peer_splits_across_frames();
  WT_TEST_MAIN_END("wt_http3_driver_streams");
}
