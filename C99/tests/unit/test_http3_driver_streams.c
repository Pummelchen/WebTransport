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

int main(void) {
  test_the_streams_a_session_start_opens();
  WT_TEST_MAIN_END("wt_http3_driver_streams");
}
