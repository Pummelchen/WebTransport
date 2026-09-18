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

#include <string.h>

#include "webtransport/http3/endpoint.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

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
  WT_EXPECT_OK(
      "our QPACK encoder prefix writes",
      wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_ENCODER, (uint64_t)bytes[0]);
  WT_EXPECT_STATUS(
      "and not twice", WT_ERR_STATE,
      wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, &w));

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK(
      "our QPACK decoder prefix writes",
      wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_DECODER, (uint64_t)bytes[0]);
  WT_EXPECT_STATUS(
      "and not twice", WT_ERR_STATE,
      wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER, &w));

  /* A push stream is not ours to open, and a WebTransport stream is opened by the session
   * layer with a prefix naming its session -- not here, where there is no session yet. */
  WT_EXPECT_STATUS("a push prefix is not ours", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_PUSH, &w));
  WT_EXPECT_STATUS(
      "nor a WebTransport one", WT_ERR_INVALID_ARGUMENT,
      wt_http3_endpoint_write_prefix(&endpoint, WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, &w));
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
  WT_EXPECT_STATUS(
      "a second control stream is a connection error", WT_ERR_PROTOCOL,
      wt_http3_endpoint_on_uni_stream(&client, 7U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with the stream creation code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  /* The QPACK streams, once each. */
  write_type(bytes, &length, WT_HTTP3_STREAM_QPACK_ENCODER);
  WT_EXPECT_OK("a QPACK encoder stream is classified",
               wt_http3_endpoint_on_uni_stream(&client, 11U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_INT("as the encoder", (int)WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, (int)kind);
  WT_EXPECT_STATUS(
      "and only one is allowed", WT_ERR_PROTOCOL,
      wt_http3_endpoint_on_uni_stream(&client, 15U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with the same code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  write_type(bytes, &length, WT_HTTP3_STREAM_QPACK_DECODER);
  WT_EXPECT_OK("a QPACK decoder stream is classified",
               wt_http3_endpoint_on_uni_stream(&client, 19U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_INT("as the decoder", (int)WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER, (int)kind);
  WT_EXPECT_STATUS(
      "and only one is allowed", WT_ERR_PROTOCOL,
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
  WT_EXPECT_STATUS(
      "classifying a stream twice is a caller error", WT_ERR_STATE,
      wt_http3_endpoint_on_uni_stream(&client, 27U, bytes, length, NULL, &kind, &error));

  /* Push is refused deterministically and differently by role: a client did not ask for
   * one, and a client may not send one at all. */
  write_type(bytes, &length, WT_HTTP3_STREAM_PUSH);
  WT_EXPECT_STATUS(
      "an unrequested push is an identifier error for a client", WT_ERR_PROTOCOL,
      wt_http3_endpoint_on_uni_stream(&client, 39U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with that code", WT_HTTP3_ID_ERROR, (uint64_t)error);
  WT_EXPECT_STATUS(
      "and a stream creation error for a server", WT_ERR_PROTOCOL,
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

  /* RFC 9114 section 7.2.7: a CLIENT that receives MAX_PUSH_ID MUST treat it as H3_FRAME_UNEXPECTED. Only the
   * ENDPOINT knows its own role, which is why the check belongs here rather than in the control stream -- and the
   * rule used to live only in a table (`wt_http3_frame_allowed`) that nothing calls, so it was never applied. */
  WT_EXPECT_STATUS(
      "a client refuses a server's MAX_PUSH_ID", WT_ERR_PROTOCOL,
      wt_http3_endpoint_on_control_frame(&endpoint, WT_HTTP3_FRAME_MAX_PUSH_ID, &error));
  WT_EXPECT_U64("as an unexpected frame", (uint64_t)WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
  {
    /* The server side of the same frame: MAX_PUSH_ID is a client's to send, so a server takes it. */
    wt_http3_endpoint_t server;
    uint8_t server_bytes[8];
    size_t server_length = 0U;
    wt_http3_error_t server_error = WT_HTTP3_NO_ERROR;

    wt_http3_endpoint_init(&server, WT_HTTP3_ROLE_SERVER);
    write_type(server_bytes, &server_length, WT_HTTP3_STREAM_CONTROL);
    WT_EXPECT_OK("a server classifies the control stream",
                 wt_http3_endpoint_on_uni_stream(&server, 3U, server_bytes, server_length, NULL,
                                                 NULL, &server_error));
    WT_EXPECT_OK("takes its SETTINGS", wt_http3_endpoint_on_control_frame(
                                           &server, WT_HTTP3_FRAME_SETTINGS, &server_error));
    WT_EXPECT_OK(
        "and accepts MAX_PUSH_ID from a client",
        wt_http3_endpoint_on_control_frame(&server, WT_HTTP3_FRAME_MAX_PUSH_ID, &server_error));
  }

  /* The peer's control stream ending is the error itself, whether or not SETTINGS came. */
  WT_EXPECT_STATUS("closing the control stream is an error", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream_end(&endpoint, 3U, &error));
  WT_EXPECT_U64("with the closed-critical-stream code", WT_HTTP3_CLOSED_CRITICAL_STREAM,
                (uint64_t)error);
  WT_EXPECT_U64("and it is forgotten", 0U, (uint64_t)wt_http3_endpoint_stream_count(&endpoint));

  /* Any other stream ending is not an error, and neither is one that was never tracked. */
  WT_EXPECT_OK("an untracked stream ending is nothing",
               wt_http3_endpoint_on_uni_stream_end(&endpoint, 99U, &error));
  WT_EXPECT_OK("and so is a QPACK stream ending",
               wt_http3_endpoint_on_uni_stream_end(&endpoint, 11U, &error));
}

static void test_the_peer_table_is_bounded(void) {
  /* A PUSH stream's prefix: section 6.2.1's type 0x01. */
  static const uint8_t push_prefix[1] = {0x01U};
  static const size_t push_prefix_length = 1U;
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
  WT_EXPECT_STATUS(
      "one more is limited", WT_ERR_LIMIT,
      wt_http3_endpoint_on_uni_stream(&endpoint, 4096U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);

  /* And a PUSH stream at the bound is where an audit found an OUT-OF-BOUNDS WRITE: that branch recorded the
   * stream BEFORE the `stream_count >= MAX` check below it -- which it returned before reaching -- so
   * `streams[32]` was written one past the end of a 32-entry array and `stream_count` was overwritten with the
   * peer's stream ID (32 became 133 in the audit's harness, which is how the corruption was visible). The
   * refusal is asserted here, and so is the count, because the count was the evidence. */
  WT_EXPECT_STATUS("a PUSH stream at the bound is refused", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_uni_stream(&endpoint, 8192U, push_prefix,
                                                   push_prefix_length, NULL, &kind, &error));
  WT_EXPECT_U64("and leaves the table as it was", (uint64_t)WT_HTTP3_ENDPOINT_STREAMS_MAX,
                (uint64_t)wt_http3_endpoint_stream_count(&endpoint));

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
  WT_EXPECT_OK("and its state moves", wt_http3_endpoint_request_state(&client, 0U, &state));
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
  WT_EXPECT_OK("a second request stream opens",
               wt_http3_endpoint_open_request(&client, 4U, &error));
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
  WT_EXPECT_OK("then the state is read", wt_http3_endpoint_request_state(&client, 0U, &state));
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

/* A field section built the way a peer builds one: the prefix, then one literal line per
 * field, all against the static table so no dynamic state is needed. */
static size_t build_section(uint8_t *out, size_t capacity, const char *name, const char *value) {
  wt_writer_t w = wt_writer_init(out, capacity);
  wt_qpack_header_prefix_t prefix;
  wt_qpack_field_line_t line;
  uint8_t scratch[64];

  prefix.required_insert_count = 0U;
  prefix.base = 0U;
  line.kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  line.never_indexed = 0;
  line.index = 0U;
  line.name_huffman = 0;
  line.name = (const uint8_t *)name;
  line.name_length = strlen(name);
  line.value = (const uint8_t *)value;
  line.value_length = strlen(value);
  line.value_huffman = 0;
  line.bytes_consumed = 0U;

  if (wt_qpack_field_section_encode(&w, &prefix, 0U, &line, 1U, scratch, sizeof(scratch)) !=
      WT_OK) {
    return 0U;
  }
  return wt_writer_offset(&w);
}

static void test_request_headers_are_decoded(void) {
  wt_http3_endpoint_t server;
  wt_http3_endpoint_stream_kind_t unused = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_message_t message;
  wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint8_t payload[128];
  uint8_t scratch[256];
  size_t length;
  size_t i;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;

  wt_http3_endpoint_init(&server, WT_HTTP3_ROLE_SERVER);

  /* A capacity below 32 makes MaxEntries zero, and then no section may reference the
   * dynamic table: the state to configure before reading anything. */
  WT_EXPECT_OK("a decoder capacity is set", wt_http3_endpoint_set_decoder_capacity(&server, 0U));
  WT_EXPECT_OK("and setting it again is not a reconfiguration",
               wt_http3_endpoint_set_decoder_capacity(&server, 0U));
  /* AUD-0027: a capacity this build cannot honour is refused rather than accepted in silence.
   * Nothing parses the QPACK encoder stream, so the table could never be filled, and an endpoint
   * that believed otherwise would read every field-section prefix against an empty window. */
  WT_EXPECT_STATUS("a capacity this build cannot fill is unsupported", WT_ERR_UNSUPPORTED,
                   wt_http3_endpoint_set_decoder_capacity(&server, 4096U));
  WT_EXPECT_U64("and the endpoint keeps the capacity it had", 0U,
                (uint64_t)server.decoder_table.capacity);

  WT_EXPECT_OK("the server receives a request stream",
               wt_http3_endpoint_on_request_stream(&server, 0U, &error));

  /* A field section reaching the message decoder: the endpoint owns the decoder state and
   * the ordering rule, and hands back a decoded request. */
  length = build_section(payload, sizeof(payload), "x-test", "one");
  WT_EXPECT_TRUE("a field section was built", length != 0U);
  /* A request's FIRST section IS the request line, so a section carrying only regular
   * fields is not a request: the message layer refuses it and names the code. The endpoint
   * does not second-guess that judgement -- it owns the ordering rule and the decoder state,
   * not the shape of a request. */
  WT_EXPECT_STATUS("a first section without the request line is refused", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_request_headers(&server, 0U, payload, length, scratch,
                                                        sizeof(scratch), &message, &error));
  WT_EXPECT_U64("with the message error code", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  WT_EXPECT_OK("while the stream's frame state still moved",
               wt_http3_endpoint_request_state(&server, 0U, &state));
  WT_EXPECT_INT("to the body", (int)WT_HTTP3_REQUEST_BODY, (int)state);

  /* An extended CONNECT: the pseudo-headers are the request line, and the draft-16 layer
   * decides what they mean. The endpoint does not, which is the separation under test. */
  {
    static uint8_t section[256];
    wt_writer_t w = wt_writer_init(section, sizeof(section));
    wt_qpack_header_prefix_t prefix;
    wt_qpack_field_line_t lines[5];
    uint8_t local_scratch[256];
    const char *names[5];
    const char *values[5];

    names[0] = ":method";
    values[0] = "CONNECT";
    names[1] = ":scheme";
    values[1] = "https";
    names[2] = ":authority";
    values[2] = "example.com";
    names[3] = ":path";
    values[3] = "/chat";
    names[4] = ":protocol";
    values[4] = WT_WEBTRANSPORT_PROTOCOL_TOKEN;

    prefix.required_insert_count = 0U;
    prefix.base = 0U;
    for (i = 0U; i < 5U; i++) {
      lines[i].kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
      lines[i].never_indexed = 0;
      lines[i].index = 0U;
      lines[i].name_huffman = 0;
      lines[i].name = (const uint8_t *)names[i];
      lines[i].name_length = strlen(names[i]);
      lines[i].value = (const uint8_t *)values[i];
      lines[i].value_length = strlen(values[i]);
      lines[i].value_huffman = 0;
      lines[i].bytes_consumed = 0U;
    }
    WT_EXPECT_OK("a CONNECT section encodes",
                 wt_qpack_field_section_encode(&w, &prefix, 0U, lines, 5U, local_scratch,
                                               sizeof(local_scratch)));

    WT_EXPECT_OK("and a second request stream opens",
                 wt_http3_endpoint_on_request_stream(&server, 4U, &error));
    WT_EXPECT_OK("whose CONNECT decodes",
                 wt_http3_endpoint_on_request_headers(&server, 4U, section, wt_writer_offset(&w),
                                                      scratch, sizeof(scratch), &message, &error));
    WT_EXPECT_U64("with the method's length", 7U, (uint64_t)message.method_length);
    WT_EXPECT_BYTES("the method", (const uint8_t *)"CONNECT", message.method,
                    message.method_length);
    WT_EXPECT_BYTES("the protocol", (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN,
                    message.protocol, message.protocol_length);

    /* The decision is the draft-16 layer's, and it is taken from the decoded message
     * without this layer knowing what a WebTransport request is. */
    policy.authority = "example.com";
    policy.path = "/chat";
    policy.wt_enabled = 1;
    WT_EXPECT_OK("the session layer accepts it",
                 wt_webtransport_session_request_validate(&message, &policy, &decision, &error));
    WT_EXPECT_INT("as an accepted WebTransport request", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT,
                  (int)decision.outcome);

    /* A trailer may not carry pseudo-headers (section 4.1), and this layer is where that is
     * enforced, because the message decoder has one request shape and one response shape. */
    wt_http3_endpoint_on_request_frame(&server, 4U, WT_HTTP3_FRAME_DATA, &error);
    {
      static uint8_t trailer[256];
      wt_writer_t tw = wt_writer_init(trailer, sizeof(trailer));
      wt_qpack_field_line_t line;
      wt_qpack_header_prefix_t tprefix;
      uint8_t trailer_scratch[128];
      tprefix.required_insert_count = 0U;
      tprefix.base = 0U;
      line.kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
      line.never_indexed = 0;
      line.index = 0U;
      line.name_huffman = 0;
      line.name = (const uint8_t *)":path";
      line.name_length = 5U;
      line.value = (const uint8_t *)"/again";
      line.value_length = 6U;
      line.value_huffman = 0;
      line.bytes_consumed = 0U;
      WT_EXPECT_OK("a pseudo-header trailer encodes",
                   wt_qpack_field_section_encode(&tw, &tprefix, 0U, &line, 1U, trailer_scratch,
                                                 sizeof(trailer_scratch)));
      WT_EXPECT_STATUS("and is refused", WT_ERR_PROTOCOL,
                       wt_http3_endpoint_on_request_headers(&server, 4U, trailer,
                                                            wt_writer_offset(&tw), scratch,
                                                            sizeof(scratch), &message, &error));
      WT_EXPECT_U64("with the message error code", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
    }
  }

  /* A HEADERS frame on a stream this endpoint is not tracking is the caller's ordering. */
  length = build_section(payload, sizeof(payload), "x-test", "two");
  WT_EXPECT_STATUS("an untracked stream is a state error", WT_ERR_STATE,
                   wt_http3_endpoint_on_request_headers(&server, 8U, payload, length, scratch,
                                                        sizeof(scratch), &message, &error));
  (void)unused;
}

/* The encode side, which is the decode path read backwards: a client writes the extended
 * CONNECT it wants, and the section it produces is exactly what a server's decode path
 * reads. The test closes that loop rather than asserting against hand-written bytes, because
 * a round trip through both directions is what makes the two agree by construction. */
static void test_a_client_writes_the_request_it_means(void) {
  wt_http3_endpoint_t client;
  wt_http3_endpoint_t server;
  wt_http3_message_t outgoing;
  wt_http3_message_t decoded;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint8_t wire[512];
  uint8_t section[256];
  uint8_t scratch[256];
  size_t length = 0U;
  wt_writer_t w;
  wt_cursor_t cursor;
  wt_http3_frame_t frame;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;

  wt_http3_endpoint_init(&client, WT_HTTP3_ROLE_CLIENT);
  wt_http3_endpoint_init(&server, WT_HTTP3_ROLE_SERVER);
  WT_EXPECT_OK("the server receives a request stream",
               wt_http3_endpoint_on_request_stream(&server, 0U, &error));

  /* What the draft-16 layer wants to send: an extended CONNECT for a WebTransport session.
   * The endpoint does not build these fields -- the layer that knows what a WebTransport
   * request is does -- and that separation is the point of the split. */
  outgoing.type = WT_HTTP3_HEADER_REQUEST;
  outgoing.method = (const uint8_t *)"CONNECT";
  outgoing.method_length = 7U;
  outgoing.scheme = (const uint8_t *)"https";
  outgoing.scheme_length = 5U;
  outgoing.authority = (const uint8_t *)"example.com";
  outgoing.authority_length = 11U;
  outgoing.path = (const uint8_t *)"/chat";
  outgoing.path_length = 5U;
  outgoing.protocol = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN;
  outgoing.protocol_length = strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN);
  outgoing.status = 0U;
  outgoing.has_status = 0;

  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("the client writes its request",
               wt_http3_endpoint_write_headers(&client, &outgoing, 0U, section, sizeof(section), &w,
                                               &error));
  length = wt_writer_offset(&w);
  WT_EXPECT_TRUE("producing bytes", length > 0U);

  /* The frame is a HEADERS frame, and its length prefix MEASURES the section: the reader
   * finds the section exactly where the writer put it. */
  cursor = wt_cursor_init(wire, length);
  WT_EXPECT_OK("and they decode as a frame", wt_http3_frame_decode(&cursor, &frame, &error));
  WT_EXPECT_U64("which is HEADERS", WT_HTTP3_FRAME_HEADERS, frame.type);
  WT_EXPECT_U64("with no bytes left over", 0U, (uint64_t)wt_cursor_remaining(&cursor));

  /* The server reads it with its own decoder state and gets back what the client meant. */
  WT_EXPECT_OK("the server decodes it",
               wt_http3_endpoint_on_request_headers(&server, 0U, frame.payload, frame.length,
                                                    scratch, sizeof(scratch), &decoded, &error));
  WT_EXPECT_BYTES("the method", (const uint8_t *)"CONNECT", decoded.method, decoded.method_length);
  WT_EXPECT_BYTES("the scheme", (const uint8_t *)"https", decoded.scheme, decoded.scheme_length);
  WT_EXPECT_BYTES("the authority", (const uint8_t *)"example.com", decoded.authority,
                  decoded.authority_length);
  WT_EXPECT_BYTES("the path", (const uint8_t *)"/chat", decoded.path, decoded.path_length);
  WT_EXPECT_BYTES("and the protocol", (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN,
                  decoded.protocol, decoded.protocol_length);

  /* And the draft-16 layer accepts what came out of the round trip. */
  policy.authority = "example.com";
  policy.path = "/chat";
  policy.wt_enabled = 1;
  WT_EXPECT_OK("the session layer accepts the round trip",
               wt_webtransport_session_request_validate(&decoded, &policy, &decision, &error));
  WT_EXPECT_INT("as a WebTransport request", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT,
                (int)decision.outcome);

  /* A response, which is the other shape this encoder writes. */
  {
    wt_http3_message_t response;
    wt_http3_message_t read_back;
    response.type = WT_HTTP3_HEADER_RESPONSE;
    response.method = NULL;
    response.method_length = 0U;
    response.scheme = NULL;
    response.scheme_length = 0U;
    response.authority = NULL;
    response.authority_length = 0U;
    response.path = NULL;
    response.path_length = 0U;
    response.protocol = NULL;
    response.protocol_length = 0U;
    response.status = 200U;
    response.has_status = 1;

    w = wt_writer_init(wire, sizeof(wire));
    WT_EXPECT_OK("a response writes",
                 wt_http3_endpoint_write_headers(&client, &response, 0U, section, sizeof(section),
                                                 &w, &error));
    cursor = wt_cursor_init(wire, wt_writer_offset(&w));
    WT_EXPECT_OK("and decodes as a frame", wt_http3_frame_decode(&cursor, &frame, &error));
    WT_EXPECT_OK("whose section reads back",
                 wt_http3_message_decode(&read_back, WT_HTTP3_HEADER_RESPONSE, frame.payload,
                                         frame.length, NULL, 0U, 0U, scratch, sizeof(scratch),
                                         &error));
    WT_EXPECT_INT("with the status", 1, read_back.has_status);
    WT_EXPECT_U64("the response carried", 200U, read_back.status);

    /* A response with no status is not a response. */
    response.has_status = 0;
    w = wt_writer_init(wire, sizeof(wire));
    WT_EXPECT_STATUS("a response without a status is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_http3_endpoint_write_headers(&client, &response, 0U, section,
                                                     sizeof(section), &w, &error));
  }

  /* A request with no method is not a request either. */
  outgoing.method = NULL;
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_STATUS("a request without a method is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_endpoint_write_headers(&client, &outgoing, 0U, section, sizeof(section),
                                                   &w, &error));
  outgoing.method = (const uint8_t *)"CONNECT";

  /* The caller's scratch is a bound, and running into it is WT_ERR_LIMIT with no error code:
   * it is this endpoint's buffer, not anything the peer did. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_STATUS(
      "a section that does not fit the scratch is limited", WT_ERR_LIMIT,
      wt_http3_endpoint_write_headers(&client, &outgoing, 0U, section, 4U, &w, &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
  WT_EXPECT_U64("and nothing written", 0U, (uint64_t)wt_writer_offset(&w));
}

int main(void) {
  test_our_own_streams_exist_once();
  test_peer_streams_are_classified();
  test_control_frames_are_forwarded();
  test_the_peer_table_is_bounded();
  test_request_streams_follow_the_roles();
  test_request_headers_are_decoded();
  test_a_client_writes_the_request_it_means();
  WT_TEST_MAIN_END("wt_http3_endpoint");
}
