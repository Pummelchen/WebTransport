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
#include "webtransport/http3/qpack.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "test_http3_endpoint_requests_support.h"


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
  /* AUD-0027 refused a NON-ZERO capacity here, because nothing applied the encoder stream and a
   * table that could never be filled would make every dynamic reference in a peer's field
   * section fail with a decompression error that blamed the peer. Both halves exist now -- the
   * encoder stream is applied and the insertions are acknowledged -- so a capacity means what it
   * says. What is still refused is changing it after the fact: the peer has been inserting
   * against the old number, and the refusal that protects against silently discarding those
   * insertions is the part of AUD-0027 that survives. */
  WT_EXPECT_STATUS("a different capacity afterwards is a state error", WT_ERR_STATE,
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
     * enforced, because the message decoder has one request shape and one response shape.
     *
     * AUD-0036: the section has to be a COMPLETE request -- `:method`, `:scheme` and `:path` --
     * or the message decoder refuses it first and the rule below is never reached. The case this
     * replaces carried only `:path`, so it passed with the trailer rule DELETED: the refusal it
     * asserted was the missing `:method`, not the pseudo-header. A section that decodes cleanly
     * leaves the trailer rule as the only thing that can refuse it. */
    wt_http3_endpoint_on_request_frame(&server, 4U, WT_HTTP3_FRAME_DATA, &error);
    {
      static uint8_t trailer[256];
      wt_writer_t tw = wt_writer_init(trailer, sizeof(trailer));
      wt_qpack_field_line_t trailer_lines[3];
      wt_qpack_header_prefix_t tprefix;
      uint8_t trailer_scratch[128];
      tprefix.required_insert_count = 0U;
      tprefix.base = 0U;
      /* `:method GET` (17), `:scheme https` (23), `:path /` (1): the static indices RFC 9204
       * appendix A lists. */
      memset(trailer_lines, 0, sizeof(trailer_lines));
      trailer_lines[0].kind = WT_QPACK_FIELD_INDEXED_STATIC;
      trailer_lines[0].index = 17U;
      trailer_lines[1].kind = WT_QPACK_FIELD_INDEXED_STATIC;
      trailer_lines[1].index = 23U;
      trailer_lines[2].kind = WT_QPACK_FIELD_INDEXED_STATIC;
      trailer_lines[2].index = 1U;
      WT_EXPECT_OK("a pseudo-header trailer encodes",
                   wt_qpack_field_section_encode(&tw, &tprefix, 0U, trailer_lines, 3U,
                                                 trailer_scratch, sizeof(trailer_scratch)));
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

/* The receive half of the QPACK dynamic table: the peer's encoder stream fills the table this
 * endpoint advertised a capacity for, and the insertions are acknowledged. */
static void test_the_dynamic_table_is_filled_and_acknowledged(void) {
  wt_http3_endpoint_t server;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_writer_t w;
  uint8_t instructions[256];
  uint8_t acks[64];
  size_t length;
  size_t consumed = 0U;
  uint64_t inserts = 0U;

  wt_http3_endpoint_init(&server, WT_HTTP3_ROLE_SERVER);

  /* The capacity in SETTINGS is the grant, and the encoder stream is the only place an
   * instruction may arrive. Neither exists yet, so there is nothing to fill. */
  WT_EXPECT_STATUS("an insert before the stream exists is refused", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_qpack_encoder_bytes(&server, instructions, 8U, &consumed,
                                                            &inserts, &error));
  WT_EXPECT_OK("the caller grants a capacity",
               wt_http3_endpoint_set_decoder_capacity(&server, 4096U));
  WT_EXPECT_U64("which the table takes", 4096U, (uint64_t)server.decoder_table.capacity);
  WT_EXPECT_STATUS("instructions still need the stream that carries them", WT_ERR_PROTOCOL,
                   wt_http3_endpoint_on_qpack_encoder_bytes(&server, instructions, 8U, &consumed,
                                                            &inserts, &error));

  {
    const uint8_t type_prefix[1] = {0x02U};
    wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_CONTROL;
    size_t prefix_consumed = 0U;
    WT_EXPECT_OK("the peer opens its QPACK encoder stream",
                 wt_http3_endpoint_on_uni_stream(&server, 2U, type_prefix, sizeof(type_prefix),
                                                 &prefix_consumed, &kind, &error));
    WT_EXPECT_U64("classified as the encoder stream",
                  (uint64_t)WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, (uint64_t)kind);
  }

  /* One insert, built by this tree's own encoder so the test cannot drift from the wire format. */
  w = wt_writer_init(instructions, sizeof(instructions));
  WT_EXPECT_OK("an insert instruction is built",
               wt_qpack_encoder_stream_write_insert_literal(&w, (const uint8_t *)"x-a", 3U,
                                                            (const uint8_t *)"one", 3U));
  length = wt_writer_offset(&w);
  WT_EXPECT_OK("the peer's insert is applied",
               wt_http3_endpoint_on_qpack_encoder_bytes(&server, instructions, length, &consumed,
                                                        &inserts, &error));
  WT_EXPECT_U64("the whole instruction was consumed", (uint64_t)length, (uint64_t)consumed);
  WT_EXPECT_U64("and one insertion is counted", 1U, inserts);
  WT_EXPECT_U64("the table holds it", 1U, (uint64_t)server.decoder_table.count);

  /* An instruction may span two chunks of the stream. The tail stays with the caller, which is
   * why this reports how much it consumed instead of buffering the bytes itself. */
  w = wt_writer_init(instructions, sizeof(instructions));
  WT_EXPECT_OK("a second insert is built",
               wt_qpack_encoder_stream_write_insert_literal(&w, (const uint8_t *)"x-b", 3U,
                                                            (const uint8_t *)"two", 3U));
  length = wt_writer_offset(&w);
  WT_EXPECT_OK("the first half of it changes nothing",
               wt_http3_endpoint_on_qpack_encoder_bytes(&server, instructions, length - 1U,
                                                        &consumed, &inserts, &error));
  WT_EXPECT_U64("and consumes nothing", 0U, (uint64_t)consumed);
  WT_EXPECT_U64("with the count unchanged", 1U, inserts);
  WT_EXPECT_OK("the whole instruction applies once the tail arrives",
               wt_http3_endpoint_on_qpack_encoder_bytes(&server, instructions, length, &consumed,
                                                        &inserts, &error));
  WT_EXPECT_U64("consuming all of it", (uint64_t)length, (uint64_t)consumed);
  WT_EXPECT_U64("and counting the second insertion", 2U, inserts);

  /* What the peer is owed. An increment for the insertions, and a section acknowledgement when
   * the caller says the section it decoded named the table. */
  w = wt_writer_init(acks, sizeof(acks));
  WT_EXPECT_OK("the insertions are acknowledged",
               wt_http3_endpoint_write_qpack_decoder_acks(&server, 0U, 0, &w));
  WT_EXPECT_TRUE("with bytes written", wt_writer_offset(&w) > 0U);
  w = wt_writer_init(acks, sizeof(acks));
  WT_EXPECT_OK("a second call owes nothing",
               wt_http3_endpoint_write_qpack_decoder_acks(&server, 0U, 0, &w));
  WT_EXPECT_U64("and writes nothing", 0U, (uint64_t)wt_writer_offset(&w));
  w = wt_writer_init(acks, sizeof(acks));
  WT_EXPECT_OK("a section that named the table is acknowledged when asked",
               wt_http3_endpoint_write_qpack_decoder_acks(&server, 0U, 1, &w));
  WT_EXPECT_TRUE("with bytes written", wt_writer_offset(&w) > 0U);
  w = wt_writer_init(acks, sizeof(acks));
  WT_EXPECT_OK("and not when it is not",
               wt_http3_endpoint_write_qpack_decoder_acks(&server, 0U, 0, &w));
  WT_EXPECT_U64("nothing", 0U, (uint64_t)wt_writer_offset(&w));

  /* The capacity is fixed once the peer has inserted against it. */
  WT_EXPECT_STATUS("a different capacity afterwards is refused", WT_ERR_STATE,
                   wt_http3_endpoint_set_decoder_capacity(&server, 8192U));
  WT_EXPECT_OK("the same one again is not a reconfiguration",
               wt_http3_endpoint_set_decoder_capacity(&server, 4096U));
  /* Before anything was granted, zero is the ordinary case and stays legal. */
  {
    wt_http3_endpoint_t fresh;
    wt_http3_endpoint_init(&fresh, WT_HTTP3_ROLE_CLIENT);
    WT_EXPECT_OK("a client with no dynamic table",
                 wt_http3_endpoint_set_decoder_capacity(&fresh, 0U));
  }
}

int main(void) {
  test_request_headers_are_decoded();
  test_a_client_writes_the_request_it_means();
  test_the_dynamic_table_is_filled_and_acknowledged();
  WT_TEST_MAIN_END("test_http3_endpoint_requests");
}
