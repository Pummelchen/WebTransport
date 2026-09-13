/* The HTTP/3 endpoint's own streams (Phase 9).
 *
 * The tests are the lifecycle rules, which are the ones a consumer never sees and a bug in
 * which looks like a peer misbehaving: our three streams exist once each; a peer's unknown
 * stream type is IGNORED rather than failed (section 6.2.1), while a second control stream,
 * a second QPACK stream and an unrequested push stream each commit the connection to the
 * error the RFC names; the draft's WebTransport stream is classified as the layer above's
 * rather than mistaken for an unknown one; and the peer-stream table is this endpoint's
 * bound, so running into it reports WT_ERR_LIMIT with no error code instead of inventing a
 * peer error. */

#include "wt_test.h"

#include "webtransport/http3/endpoint.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"

/* The prefix a peer would send for a stream of this type: its varint, shortest form. */
static void write_type(uint8_t *out, size_t *length, uint64_t type) {
  wt_writer_t w = wt_writer_init(out, 16U);
  uint8_t encoded[8];
  size_t n = wt_quic_varint_encode(type, encoded, sizeof(encoded));
  wt_writer_bytes(&w, encoded, n);
  *length = wt_writer_offset(&w);
}

static void test_our_own_streams_exist_once(void) {
  wt_http3_endpoint_t endpoint;
  uint8_t bytes[16];
  size_t length = 0U;
  wt_writer_t w;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  WT_EXPECT_U64("a fresh endpoint tracks no peer streams", 0U,
                (uint64_t)wt_http3_endpoint_stream_count(&endpoint));

  /* The control stream's prefix is the type 0x00 and nothing else: its SETTINGS frame is
   * the caller's to write, because what this endpoint's settings say is its decision. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("our control prefix writes",
               wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_CONTROL, &w));
  WT_EXPECT_U64("as one byte", 1U, (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_U64("of type control", WT_HTTP3_STREAM_CONTROL, (uint64_t)bytes[0]);
  WT_EXPECT_STATUS("and a second control stream is refused", WT_ERR_STATE,
                   wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_CONTROL, &w));

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("our QPACK encoder prefix writes",
               wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_ENCODER, (uint64_t)bytes[0]);
  WT_EXPECT_STATUS("and not twice", WT_ERR_STATE,
                   wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER,
                                                  &w));

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("our QPACK decoder prefix writes",
               wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_DECODER, (uint64_t)bytes[0]);
  WT_EXPECT_STATUS("and not twice", WT_ERR_STATE,
                   wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER,
                                                  &w));

  /* A push stream is not ours to open, and a WebTransport stream is opened by the session
   * layer with a prefix naming its session -- not here, where there is no session yet. */
  WT_EXPECT_STATUS("a push prefix is not ours", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_PUSH, &w));
  WT_EXPECT_STATUS("nor a WebTransport one", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT,
                                                  &w));
  (void)length;
}

static void test_peer_streams_are_classified(void) {
  wt_http3_endpoint_t client;
  wt_http3_endpoint_t server;
  uint8_t bytes[16];
  size_t length = 0U;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_endpoint_init(&client, WT_HTTP3_ROLE_CLIENT);
  wt_http3_endpoint_init(&server, WT_HTTP3_ROLE_SERVER);

  /* The peer's control stream, then a second one: section 6.2.1 makes one per connection. */
  write_type(bytes, &length, WT_HTTP3_STREAM_CONTROL);
  WT_EXPECT_OK("the peer's control stream is classified",
               wt_http3_endpoint_on_uni_stream(&client, 3U, bytes, length, &length, &kind, &error));
  WT_EXPECT_INT("as control", (int)WT_HTTP3_ENDPOINT_STREAM_CONTROL, (int)kind);
  WT_EXPECT_INT("and recorded", (int)WT_HTTP3_ENDPOINT_STREAM_CONTROL,
                (int)wt_http3_endpoint_stream_kind(&client, 3U));
  WT_EXPECT_STATUS("a second control stream is a connection error", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream(&client, 7U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with the stream creation code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  /* The QPACK streams, once each. */
  write_type(bytes, &length, WT_HTTP3_STREAM_QPACK_ENCODER);
  WT_EXPECT_OK("a QPACK encoder stream is classified",
               wt_http3_endpoint_on_uni_stream(&client, 11U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_INT("as the encoder", (int)WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, (int)kind);
  WT_EXPECT_STATUS("and only one is allowed", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream(&client, 15U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with the same code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  write_type(bytes, &length, WT_HTTP3_STREAM_QPACK_DECODER);
  WT_EXPECT_OK("a QPACK decoder stream is classified",
               wt_http3_endpoint_on_uni_stream(&client, 19U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_INT("as the decoder", (int)WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER, (int)kind);
  WT_EXPECT_STATUS("and only one is allowed", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream(&client, 23U, bytes, length, NULL, &kind, &error));

  /* The draft's WebTransport unidirectional stream: not HTTP/3's to interpret, so it is
   * the layer above's, not an unknown type to ignore. */
  write_type(bytes, &length, WT_WEBTRANSPORT_STREAM_UNI);
  WT_EXPECT_OK("a WebTransport stream is classified",
               wt_http3_endpoint_on_uni_stream(&client, 27U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_INT("as the session layer's", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);
  WT_EXPECT_INT("and recognised again", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT,
                (int)wt_http3_endpoint_stream_kind(&client, 27U));

  /* An unknown type is NOT an error: the caller is told so it can stop reading. */
  write_type(bytes, &length, 0x21U);
  WT_EXPECT_OK("an unknown stream type is accepted",
               wt_http3_endpoint_on_uni_stream(&client, 31U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_INT("as unknown", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN, (int)kind);
  WT_EXPECT_INT("and not recorded", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN,
                (int)wt_http3_endpoint_stream_kind(&client, 31U));

  /* A stream whose prefix has not fully arrived is incomplete, and incomplete is not
   * malformed on a stream. */
  WT_EXPECT_STATUS("a partial type prefix is truncated", WT_ERR_TRUNCATED,
                   wt_http3_endpoint_on_uni_stream(&client, 35U, (const uint8_t *)"\x40", 1U, NULL,
                                                   &kind, &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
  WT_EXPECT_OK("and the rest of it later",
               wt_http3_endpoint_on_uni_stream(&client, 35U, (const uint8_t *)"\x40\x7f", 2U, NULL,
                                               &kind, &error));

  /* Classifying the same stream twice means the caller lost its place. */
  write_type(bytes, &length, WT_WEBTRANSPORT_STREAM_UNI);
  WT_EXPECT_STATUS("classifying a stream twice is a caller error", WT_ERR_STATE,
                   wt_http3_endpoint_on_uni_stream(&client, 27U, bytes, length, NULL, &kind, &error));

  /* Push is refused deterministically and differently by role: a client did not ask for
   * one, and a client may not send one at all. */
  write_type(bytes, &length, WT_HTTP3_STREAM_PUSH);
  WT_EXPECT_STATUS("an unrequested push is an identifier error for a client", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream(&client, 39U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with that code", WT_HTTP3_ID_ERROR, (uint64_t)error);
  WT_EXPECT_STATUS("and a stream creation error for a server", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream(&server, 43U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with its code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);
}

static void test_control_frames_are_forwarded(void) {
  wt_http3_endpoint_t endpoint;
  uint8_t bytes[8];
  size_t length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);

  /* A frame before the peer's control stream is the caller's ordering, not a peer error. */
  WT_EXPECT_STATUS("a control frame before the stream exists is a state error", WT_ERR_STATE,
                   wt_http3_endpoint_on_control_frame(&endpoint, WT_HTTP3_FRAME_SETTINGS, &error));

  write_type(bytes, &length, WT_HTTP3_STREAM_CONTROL);
  WT_EXPECT_OK("the peer's control stream is classified",
               wt_http3_endpoint_on_uni_stream(&endpoint, 3U, bytes, length, NULL, NULL, &error));

  /* Section 6.2.1: the first frame is SETTINGS or the connection is committed to
   * H3_MISSING_SETTINGS. */
  WT_EXPECT_STATUS("a first frame that is not SETTINGS is refused", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_control_frame(&endpoint, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_U64("with the missing-settings code", WT_HTTP3_MISSING_SETTINGS, (uint64_t)error);
  WT_EXPECT_OK("SETTINGS is accepted",
               wt_http3_endpoint_on_control_frame(&endpoint, WT_HTTP3_FRAME_SETTINGS, &error));
  WT_EXPECT_STATUS("and a second SETTINGS is not", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_control_frame(&endpoint, WT_HTTP3_FRAME_SETTINGS, &error));
  WT_EXPECT_U64("with the unexpected-frame code", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);

  /* The peer's control stream ending is the error itself, whether or not SETTINGS came. */
  WT_EXPECT_STATUS("closing the control stream is an error", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream_end(&endpoint, 3U, &error));
  WT_EXPECT_U64("with the closed-critical-stream code", WT_HTTP3_CLOSED_CRITICAL_STREAM,
                (uint64_t)error);
  WT_EXPECT_U64("and it is forgotten", 0U, (uint64_t)wt_http3_endpoint_stream_count(&endpoint));

  /* Any other stream ending is not an error, and neither is one that was never tracked. */
  WT_EXPECT_OK("an untracked stream ending is nothing", wt_http3_endpoint_on_uni_stream_end(
                                                           &endpoint, 99U, &error));
  WT_EXPECT_OK("and so is a QPACK stream ending",
               wt_http3_endpoint_on_uni_stream_end(&endpoint, 11U, &error));
}

static void test_the_peer_table_is_bounded(void) {
  wt_http3_endpoint_t endpoint;
  uint8_t bytes[8];
  size_t length = 0U;
  size_t i;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  write_type(bytes, &length, WT_WEBTRANSPORT_STREAM_UNI);

  for (i = 0U; i < (size_t)WT_HTTP3_ENDPOINT_STREAMS_MAX; i++) {
    WT_EXPECT_OK("a WebTransport stream is tracked",
                 wt_http3_endpoint_on_uni_stream(&endpoint, 4U + (uint64_t)i * 4U, bytes, length,
                                                 NULL, &kind, &error));
  }
  WT_EXPECT_U64("the table is full", (uint64_t)WT_HTTP3_ENDPOINT_STREAMS_MAX,
                (uint64_t)wt_http3_endpoint_stream_count(&endpoint));

  /* One past the bound is THIS endpoint's limit, with no error code: the peer did nothing
   * wrong, and inventing a code for it would blame the peer for our table. */
  WT_EXPECT_STATUS("one more is limited", WT_ERR_LIMIT,
                   wt_http3_endpoint_on_uni_stream(&endpoint, 4096U, bytes, length, NULL, &kind,
                                                   &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);

  /* A control stream still gets in, because the bound is about what this endpoint tracks
   * and the critical streams are what it tracks first. */
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  write_type(bytes, &length, WT_HTTP3_STREAM_CONTROL);
  WT_EXPECT_OK("the control stream fits",
               wt_http3_endpoint_on_uni_stream(&endpoint, 3U, bytes, length, NULL, &kind, &error));
}

static void test_request_streams_follow_the_roles(void) {
  wt_http3_endpoint_t client;
  wt_http3_endpoint_t server;
  wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint8_t bytes[8];
  size_t length = 0U;
  size_t i;

  wt_http3_endpoint_init(&client, WT_HTTP3_ROLE_CLIENT);
  wt_http3_endpoint_init(&server, WT_HTTP3_ROLE_SERVER);

  /* A client opens a request stream; that stream IS a WebTransport session once its
   * extended CONNECT is accepted. */
  WT_EXPECT_OK("a client opens a request stream",
               wt_http3_endpoint_open_request(&client, 0U, &error));
  WT_EXPECT_U64("which it tracks", 1U, (uint64_t)wt_http3_endpoint_request_count(&client));
  WT_EXPECT_OK("with its ordering state readable",
               wt_http3_endpoint_request_state(&client, 0U, &state));
  WT_EXPECT_INT("starting at HEADERS", (int)WT_HTTP3_REQUEST_EXPECT_HEADERS, (int)state);

  /* The request machine's rules are applied per stream, not re-implemented here. */
  WT_EXPECT_STATUS("a DATA frame before HEADERS is refused", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_request_frame(&client, 0U, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_U64("with the unexpected-frame code", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
  WT_EXPECT_OK("HEADERS is accepted",
               wt_http3_endpoint_on_request_frame(&client, 0U, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_OK("and its state moves",
               wt_http3_endpoint_request_state(&client, 0U, &state));
  WT_EXPECT_INT("to the body", (int)WT_HTTP3_REQUEST_BODY, (int)state);

  /* A frame on a stream nobody opened is the caller's ordering. */
  WT_EXPECT_STATUS("a frame on an untracked stream is a state error", WT_ERR_STATE,
                   wt_http3_endpoint_on_request_frame(&client, 4U, WT_HTTP3_FRAME_HEADERS, &error));

  /* A server cannot open one: HTTP/3 has no server-initiated request, and the peer would
   * be required to treat it as a connection error. */
  WT_EXPECT_STATUS("a server cannot open a request stream", WT_ERR_STATE,
                   wt_http3_endpoint_open_request(&server, 0U, &error));

  /* The other direction: a server receives one, and a client receiving one is a stream
   * creation error. */
  WT_EXPECT_OK("a server receives a request stream",
               wt_http3_endpoint_on_request_stream(&server, 0U, &error));
  WT_EXPECT_STATUS("a client may not receive one", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_request_stream(&client, 4U, &error));
  WT_EXPECT_U64("with the stream creation code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  /* Opening the same stream twice means the caller lost its place. */
  WT_EXPECT_STATUS("opening a stream twice is a state error", WT_ERR_STATE,
                   wt_http3_endpoint_open_request(&client, 0U, &error));

  /* Ending before HEADERS is H3_REQUEST_INCOMPLETE -- the code section 4.1 defines for
   * aborting the response, not for closing the connection -- and the stream is forgotten. */
  WT_EXPECT_OK("a second request stream opens", wt_http3_endpoint_open_request(&client, 4U, &error));
  WT_EXPECT_STATUS("ending it before HEADERS is incomplete", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_request_end(&client, 4U, &error));
  WT_EXPECT_U64("with that code", WT_HTTP3_REQUEST_INCOMPLETE, (uint64_t)error);
  WT_EXPECT_U64("and it is forgotten", 1U, (uint64_t)wt_http3_endpoint_request_count(&client));

  /* A reset is not a frame-ordering matter: it just closes the stream out. */
  WT_EXPECT_OK("a third request stream opens", wt_http3_endpoint_open_request(&client, 8U, &error));
  WT_EXPECT_OK("and a reset closes it", wt_http3_endpoint_on_request_reset(&client, 8U));
  WT_EXPECT_U64("forgotten too", 1U, (uint64_t)wt_http3_endpoint_request_count(&client));
  WT_EXPECT_STATUS("so its state is gone", WT_ERR_STATE,
                   wt_http3_endpoint_request_state(&client, 8U, &state));
  WT_EXPECT_STATUS("and a reset of an untracked stream is a state error", WT_ERR_STATE,
                   wt_http3_endpoint_on_request_reset(&client, 12U));

  /* A complete request: HEADERS, DATA, the trailer. */
  WT_EXPECT_OK("the tracked stream takes DATA",
               wt_http3_endpoint_on_request_frame(&client, 0U, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_OK("and a trailer",
               wt_http3_endpoint_on_request_frame(&client, 0U, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_OK("then the state is read",
               wt_http3_endpoint_request_state(&client, 0U, &state));
  WT_EXPECT_INT("as complete", (int)WT_HTTP3_REQUEST_COMPLETE, (int)state);
  WT_EXPECT_STATUS("and nothing follows a trailer", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_request_frame(&client, 0U, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_OK("a clean end is fine", wt_http3_endpoint_on_request_end(&client, 0U, &error));

  /* The request table is this endpoint's bound, with no error code. */
  for (i = 0U; i < (size_t)WT_HTTP3_ENDPOINT_REQUESTS_MAX; i++) {
    WT_EXPECT_OK("a request stream opens",
                 wt_http3_endpoint_open_request(&client, 100U + (uint64_t)i * 4U, &error));
  }
  WT_EXPECT_STATUS("one past the bound is limited", WT_ERR_LIMIT,
                   wt_http3_endpoint_open_request(&client, 4096U, &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
  /* A stream the endpoint already tracks is the caller's error even when the table is
   * full: the duplicate is found before the bound. */
  WT_EXPECT_STATUS("while a duplicate is still a state error", WT_ERR_STATE,
                   wt_http3_endpoint_open_request(&client, 100U, &error));
  (void)bytes;
  (void)length;
}

int main(void) {
  test_our_own_streams_exist_once();
  test_peer_streams_are_classified();
  test_control_frames_are_forwarded();
  test_the_peer_table_is_bounded();
  test_request_streams_follow_the_roles();
  WT_TEST_MAIN_END("wt_http3_endpoint");
}
