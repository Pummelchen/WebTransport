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
               wt_http3_driver_start_session(&driver, &transport, &settings, "example.com", "/chat",
                                             0U, 1000U, &request_stream_id, &error));
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
                     recording.streams[0].bytes[5] == 0xf0U &&
                     recording.streams[0].bytes[6] == 0x00U &&
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
                 wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, payload,
                                         (size_t)frame_length, NULL, 0U, 0U, scratch,
                                         sizeof(scratch), &decode_error));
    WT_EXPECT_BYTES("into a CONNECT", (const uint8_t *)"CONNECT", message.method, 7U);
    WT_EXPECT_BYTES("for the WebTransport protocol",
                    (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN, message.protocol,
                    strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN));
    WT_EXPECT_BYTES("at the path asked for", (const uint8_t *)"/chat", message.path, 5U);
    WT_EXPECT_BYTES("for the authority asked for", (const uint8_t *)"example.com",
                    message.authority, 11U);
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

static void test_the_session_start_can_be_split_around_a_data_stream(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_settings_t settings;
  wt_http3_driver_transport_t transport;
  class_fake_t fake;
  uint64_t request_stream_id = 0U;
  uint64_t data_stream_id = 0U;
  uint64_t named = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  memset(&fake, 0, sizeof(fake));
  /* The unidirectional IDs start at 2, because 0 is a bidirectional one: a fake that handed out 0 for a
   * unidirectional stream would put the control stream where the CONNECT stream has to be. */
  fake.next_uni = 2U;
  memset(&transport, 0, sizeof(transport));
  transport.open_stream = class_open;
  transport.send_stream = class_send;
  transport.context = &fake;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the endpoint advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));

  WT_EXPECT_OK("the request stream opens",
               wt_http3_driver_open_session_stream(&driver, &transport, &settings, 1000U,
                                                   &request_stream_id, &error));
  /* The client's first bidirectional stream, which is what a CONNECT stream must be. */
  WT_EXPECT_U64("as the client's first bidirectional stream", 0U, request_stream_id);
  WT_EXPECT_U64("with nothing written on it yet", 0U, (uint64_t)fake.lengths[request_stream_id]);
  WT_EXPECT_U64("and the session ID set to it", 0U, driver.session_id);

  WT_EXPECT_OK("a data stream opens before the CONNECT",
               wt_http3_driver_open_data_stream(&driver, &transport, 0, (const uint8_t *)"early",
                                                5U, 1, 1000U, &data_stream_id));
  WT_EXPECT_U64("as the NEXT bidirectional stream", 4U, data_stream_id);
  WT_EXPECT_OK("whose session is readable",
               wt_http3_driver_data_stream_session_id(&driver, data_stream_id, &named));
  WT_EXPECT_U64("and is the request stream's ID, because the session IS its stream",
                request_stream_id, named);
  /* The draft's prefix, 0x41 and the session ID, then the message: three bytes of prefix and five of payload.
   * Asserted as a length because the recording holds what the peer would receive. */
  WT_EXPECT_U64("with the draft's prefix and the message on it", 8U,
                (uint64_t)fake.lengths[data_stream_id]);
  WT_EXPECT_U64("BEFORE the request stream has anything on it", 0U,
                (uint64_t)fake.lengths[request_stream_id]);

  WT_EXPECT_OK("the CONNECT is sent when the caller is ready",
               wt_http3_driver_send_session_request(&driver, &transport, request_stream_id,
                                                    "example.com", "/chat", 0U, 1000U, &error));
  WT_EXPECT_TRUE("which writes on the stream the first call opened",
                 fake.lengths[request_stream_id] > 0U);
  /* RFC 9114 section 7.2.1: a request's HEADERS frame, type 0x01. */
  WT_EXPECT_U64("as an HTTP/3 HEADERS frame", 0x01U, (uint64_t)fake.bytes[request_stream_id][0]);
  /* The ORDER is the claim, so it is read out of the write log rather than inferred: the session's own streams
   * (the control stream and the two QPACK ones) come first because a peer cannot interpret anything before its
   * SETTINGS, then the DATA STREAM, and the CONNECT last -- which is the whole point of the split. */
  WT_EXPECT_U64("the data stream is written second to last", data_stream_id,
                fake.send_order[fake.send_count - 2U]);
  WT_EXPECT_U64("and the request is the LAST thing written", request_stream_id,
                fake.send_order[fake.send_count - 1U]);
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
  prefix_length +=
      wt_quic_varint_encode(0U, prefix + prefix_length, sizeof(prefix) - prefix_length);

  WT_EXPECT_OK("a data stream opens and the message goes out",
               wt_http3_driver_open_data_stream(&driver, &transport, 0, k_message,
                                                sizeof(k_message), 1, 1000U, &stream_id));
  WT_EXPECT_INT("as a bidirectional one", 1, fake.opened_bidirectional);
  WT_EXPECT_U64("on the stream the transport gave", fake.stream_id, stream_id);
  WT_EXPECT_U64("carrying the prefix and then the message",
                (uint64_t)(prefix_length + sizeof(k_message)), (uint64_t)fake.sent_length);
  WT_EXPECT_BYTES("whose first bytes are the signal value and the session", prefix, fake.sent,
                  prefix_length);
  WT_EXPECT_BYTES("and whose rest is the message", k_message, fake.sent + prefix_length,
                  sizeof(k_message));
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
  WT_EXPECT_OK(
      "the answer is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("straight to the session sink", 1U, (uint64_t)sink_log.calls);
  WT_EXPECT_U64("for the stream it arrived on", stream_id, sink_log.stream_id);
  WT_EXPECT_BYTES("as the payload, unchanged", k_message, sink_log.bytes, sizeof(k_message));
  WT_EXPECT_INT("with the peer's end of stream", 1, sink_log.fin);

  /* And the other half of the rule: a stream this endpoint did NOT open is where a prefix belongs, so the same
   * bytes there are an HTTP/3 request stream's and not this session's payload. */
  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id =
      4U; /* client-initiated and bidirectional, and NOT one this endpoint opened */
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
  static const uint8_t k_prefix[] = {0x40U, 0x41U,
                                     0x00U}; /* the bidirectional signal value and session 0 */
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
  WT_EXPECT_OK(
      "the prefix frame is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("delivering nothing yet, because the prefix carries no payload", 0U,
                (uint64_t)sink_log.calls);
  WT_EXPECT_INT("but the stream is remembered as a data stream", 1,
                wt_http3_driver_is_data_stream(&driver, 4U));

  /* The message, in the NEXT frame, at a non-zero offset: this is the frame that used to be mis-routed. */
  frame.as.stream.offset = sizeof(k_prefix);
  frame.as.stream.data = k_message;
  frame.as.stream.length = sizeof(k_message);
  frame.as.stream.fin = 1;
  WT_EXPECT_OK(
      "the message frame is routed",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("straight to the session sink", 1U, (uint64_t)sink_log.calls);
  WT_EXPECT_BYTES("as the payload, unchanged", k_message, sink_log.bytes, sizeof(k_message));
  WT_EXPECT_INT("with the peer's end of stream", 1, sink_log.fin);
}

/* A frame that ends part way through at FIN is H3_FRAME_ERROR, and the driver has to SAY so (WT-158).
 *
 * RFC 9114 makes the truncated final frame a connection error of type H3_FRAME_ERROR, so closing the connection is
 * right -- but the code the peer is told must be the HTTP/3 one, and only the layer that knows it can say it. The
 * driver records it, and the connection turns that into an application close. */
static void test_a_frame_that_ends_at_fin_names_the_http3_error(void) {
  static const uint8_t k_partial[] = {
      0x01U, 0x40U}; /* a HEADERS frame whose declared length never arrives */
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  data_stream_sink_t sink_log;
  wt_http3_driver_sink_t sink;
  wt_quic_connection_t connection;
  wt_quic_frame_t frame;

  memset(&sink_log, 0, sizeof(sink_log));
  memset(&sink, 0, sizeof(sink));
  sink.context = &sink_log;
  sink.on_stream_data = data_stream_on_data;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 0U);
  WT_EXPECT_U64("a fresh driver has no error to report", (uint64_t)WT_HTTP3_NO_ERROR,
                (uint64_t)wt_http3_driver_last_error(&driver));

  /* A connection for the driver to state its refusals to: the driver knows the HTTP/3 code, so the driver is what
   * closes with it, rather than each caller translating the status (WT-159). */
  {
    static const uint8_t k_id[4] = {0x0aU, 0x0bU, 0x0cU, 0x0dU};
    wt_quic_connection_config_t config;
    memset(&config, 0, sizeof(config));
    config.role = WT_QUIC_ROLE_SERVER;
    config.version = WT_QUIC_VERSION_1;
    config.local_connection_id = k_id;
    config.local_connection_id_length = sizeof(k_id);
    config.peer_connection_id = k_id;
    config.peer_connection_id_length = sizeof(k_id);
    config.aead = WT_AEAD_AES_128_GCM;
    config.max_ack_delay = 25000U;
    config.local_max_ack_delay = 25000U;
    config.idle_timeout = 30000000U;
    config.max_datagram_size = WT_QUIC_MAX_PACKET;
    WT_EXPECT_OK("a connection initialises", wt_quic_connection_init(&connection, &config));
    wt_http3_driver_bind_connection(&driver, &connection);
  }

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = 0U;
  frame.as.stream.offset = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = k_partial;
  frame.as.stream.length = sizeof(k_partial);
  frame.as.stream.fin = 1;
  WT_EXPECT_STATUS(
      "a frame cut off by FIN is refused", WT_ERR_TRUNCATED,
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("and the refusal names H3_FRAME_ERROR", (uint64_t)WT_HTTP3_FRAME_ERROR,
                (uint64_t)wt_http3_driver_last_error(&driver));
  /* And the connection the driver is BOUND to is TOLD, as an application refusal with the HTTP/3 code: RFC 9114
   * section 8 puts an HTTP/3 error in a CONNECTION_CLOSE of type 0x1d, so the driver leaves the APPLICATION hint
   * rather than a transport code. The QUIC layer turns that hint into the close when the refusal comes back
   * through it -- covered by `test_an_http3_refusal_is_an_application_close` in `test_quic_connection`, which is
   * the other half of this chain and the half that needs a delivered frame. */
  WT_EXPECT_INT("so the connection is told the code", 1, connection.close_code_set);
  WT_EXPECT_U64("which is the HTTP/3 one", (uint64_t)WT_HTTP3_FRAME_ERROR, connection.close_code);
  WT_EXPECT_INT("in the APPLICATION form", 1, connection.close_code_application);

  /* A frame that is merely INCOMPLETE is not an error at all: more bytes are coming, and the driver waits. Its
   * last error stays clear, so a connection is never closed over a frame that has not ended. */
  frame.as.stream.fin = 0;
  WT_EXPECT_OK(
      "an incomplete frame is held rather than refused",
      wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 16384U));
  WT_EXPECT_U64("with no error to report", (uint64_t)WT_HTTP3_NO_ERROR,
                (uint64_t)wt_http3_driver_last_error(&driver));
}

/* A CONNECT stream's capsules arrive inside HTTP/3 DATA frames (WT-164, WT-249).
 *
 * Draft-16 section 5 puts the session's control messages on the CONNECT stream as CAPSULES after its one HEADERS
 * frame; RFC 9114 section 4.4 permits only DATA frames there, and RFC 9297 sections 3.1 and 3.2 make the capsule
 * protocol the CONTENTS of those frames. So the driver still FRAMES the stream, and what reaches the session's
 * sink is a DATA frame's payload. Both halves are the rules: this driver used to parse the capsule bytes as HTTP/3
 * frames, and a raw capsule -- which is what this tree then sent -- is the header of an UNKNOWN frame type, so
 * RFC 9114 section 9 had every peer IGNORE it and the peer's credit or its close was dropped without a word.
 *
 * What makes this more than a check is WHERE the mark settles: the response HEADERS and the capsule can arrive in
 * one STREAM frame, so the stream has to become a capsule stream DURING the buffer that framed its HEADERS. */

int main(void) {
  test_the_streams_a_session_start_opens();
  test_a_data_stream_this_endpoint_opened();
  test_a_data_stream_the_peer_splits_across_frames();
  test_a_frame_that_ends_at_fin_names_the_http3_error();
  test_the_session_start_can_be_split_around_a_data_stream();
  WT_TEST_MAIN_END("test_http3_driver_streams");
}
