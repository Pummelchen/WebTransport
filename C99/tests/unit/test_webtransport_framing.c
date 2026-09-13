/* WebTransport stream and datagram framing (draft-ietf-webtrans-http3-16 sections 4.2
 * and 4.3).
 *
 * The prefix is two varints and the datagram is one plus the payload, so the tests are
 * about the shape of the identifier rather than the encoding: a session ID must be the
 * CONNECT stream's -- client-initiated and bidirectional -- and a prefix naming anything
 * else describes a session that cannot exist. The datagram has the packet layer's rule
 * instead of the stream layer's, because a datagram IS the unit: one that does not hold
 * its quarter ID is malformed rather than early. */

#include "wt_test.h"

#include "webtransport/webtransport/framing.h"

static void test_session_id_shape(void) {
  WT_EXPECT_INT("stream 0 is a session", 1, wt_webtransport_is_session_stream_id(0U));
  WT_EXPECT_INT("stream 4 is too", 1, wt_webtransport_is_session_stream_id(4U));
  /* Client-initiated unidirectional (2), server-initiated (1 and 3): none is a CONNECT
   * stream, so none can be a session. */
  WT_EXPECT_INT("a unidirectional one is not", 0, wt_webtransport_is_session_stream_id(2U));
  WT_EXPECT_INT("nor a server-initiated one", 0, wt_webtransport_is_session_stream_id(1U));
  WT_EXPECT_INT("nor the server's bidirectional", 0, wt_webtransport_is_session_stream_id(3U));

  WT_EXPECT_U64("a session's quarter is its ID over four", 1U,
                wt_webtransport_quarter_stream_id(4U));
  WT_EXPECT_U64("and back again", 4U, wt_webtransport_session_id_from_quarter(1U));
  WT_EXPECT_U64("for a later session too", 40U, wt_webtransport_session_id_from_quarter(10U));
}

static void test_stream_prefix(void) {
  uint8_t bytes[16];
  wt_writer_t w;
  wt_cursor_t c;
  int unidirectional = -1;
  uint64_t session_id = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* A bidirectional prefix. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a bidirectional prefix writes",
               wt_webtransport_stream_prefix_write(&w, 0, 8U));
  /* 0x41 is above 63, so its varint is two bytes: 0x40 | the high bits, then the low
   * byte. The stream type is the VALUE, not the first byte, and a test that compared the
   * first byte with the value would be checking the varint's shape by accident. */
  WT_EXPECT_U64("as a two-byte varint", 0x40U, (uint64_t)bytes[0]);
  WT_EXPECT_U64("carrying the 0x41 type", WT_WEBTRANSPORT_STREAM_BIDI, (uint64_t)bytes[1]);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and parses", wt_webtransport_stream_prefix_parse(&c, &unidirectional, &session_id,
                                                                 &error));
  WT_EXPECT_INT("as bidirectional", 0, unidirectional);
  WT_EXPECT_U64("for its session", 8U, session_id);
  WT_EXPECT_TRUE("leaving the stream data behind", wt_cursor_at_end(&c));

  /* A unidirectional one, distinguished by its type. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a unidirectional prefix writes",
               wt_webtransport_stream_prefix_write(&w, 1, 12U));
  WT_EXPECT_U64("as a two-byte varint too", 0x40U, (uint64_t)bytes[0]);
  WT_EXPECT_U64("carrying the 0x54 type", WT_WEBTRANSPORT_STREAM_UNI, (uint64_t)bytes[1]);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and parses", wt_webtransport_stream_prefix_parse(&c, &unidirectional, &session_id,
                                                                 &error));
  WT_EXPECT_INT("as unidirectional", 1, unidirectional);
  WT_EXPECT_U64("for its session", 12U, session_id);

  /* A prefix followed by data: what is left is the stream's payload. */
  {
    static const uint8_t payload[3] = {0xaaU, 0xbbU, 0xccU};
    w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a prefix writes", wt_webtransport_stream_prefix_write(&w, 0, 4U));
    wt_writer_bytes(&w, payload, sizeof(payload));
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_OK("and parses", wt_webtransport_stream_prefix_parse(&c, &unidirectional, &session_id,
                                                                   &error));
    WT_EXPECT_U64("leaving the payload", (uint64_t)sizeof(payload),
                  (uint64_t)wt_cursor_remaining(&c));
  }

  /* A session ID that cannot be one is refused, and a writer is not allowed to invent
   * one either. */
  WT_EXPECT_STATUS("a caller cannot write a non-session prefix", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_stream_prefix_write(&w, 0, 3U));
  {
    /* 0x41 as a two-byte varint, then a server-initiated bidirectional session id (3). */
    static const uint8_t server_bidi[3] = {0x40U, 0x41U, 0x03U};
    c = wt_cursor_init(server_bidi, sizeof(server_bidi));
    WT_EXPECT_STATUS("and a peer's is refused when parsed", WT_ERR_PROTOCOL,
                     wt_webtransport_stream_prefix_parse(&c, &unidirectional, &session_id, &error));
    WT_EXPECT_U64("as an ID error", WT_HTTP3_ID_ERROR, (uint64_t)error);
  }

  /* An unknown stream type is not a WebTransport stream at all. */
  {
    static const uint8_t other_type[2] = {0x2aU, 0x04U};
    c = wt_cursor_init(other_type, sizeof(other_type));
    WT_EXPECT_STATUS("another stream type is refused", WT_ERR_PROTOCOL,
                     wt_webtransport_stream_prefix_parse(&c, &unidirectional, &session_id, &error));
    WT_EXPECT_U64("as a frame that is unexpected here", WT_HTTP3_FRAME_UNEXPECTED,
                  (uint64_t)error);
  }

  /* An incomplete prefix: a type with no session id. */
  {
    static const uint8_t type_only[1] = {0x41U};
    c = wt_cursor_init(type_only, sizeof(type_only));
    WT_EXPECT_STATUS("a prefix with no session is incomplete", WT_ERR_TRUNCATED,
                     wt_webtransport_stream_prefix_parse(&c, &unidirectional, &session_id, &error));
    WT_EXPECT_U64("with no error to send yet", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
  }
}

static void test_datagrams(void) {
  static const uint8_t payload[4] = {1U, 2U, 3U, 4U};
  uint8_t bytes[32];
  wt_writer_t w;
  uint64_t quarter = 0U;
  const uint8_t *parsed = NULL;
  size_t parsed_length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* A datagram: the quarter stream ID, then the session's data. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a datagram writes",
               wt_webtransport_datagram_write(&w, 2U, payload, sizeof(payload)));
  WT_EXPECT_OK("and parses", wt_webtransport_datagram_parse(bytes, wt_writer_offset(&w), &quarter,
                                                            &parsed, &parsed_length, &error));
  WT_EXPECT_U64("with its quarter stream ID", 2U, quarter);
  WT_EXPECT_U64("naming a session", 8U, wt_webtransport_session_id_from_quarter(quarter));
  WT_EXPECT_U64("and its payload length", (uint64_t)sizeof(payload), (uint64_t)parsed_length);
  WT_EXPECT_BYTES("and its payload", payload, parsed, sizeof(payload));

  /* An empty payload is legal: a datagram can be a signal rather than a message. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("an empty datagram writes",
               wt_webtransport_datagram_write(&w, 0U, NULL, 0U));
  WT_EXPECT_OK("and parses", wt_webtransport_datagram_parse(bytes, wt_writer_offset(&w), &quarter,
                                                            &parsed, &parsed_length, &error));
  WT_EXPECT_U64("with no payload", 0U, (uint64_t)parsed_length);

  /* A datagram that does not hold its quarter ID is malformed: a datagram is the unit,
   * so there is nothing to wait for. */
  {
    static const uint8_t too_short[1] = {0x40U};
    WT_EXPECT_STATUS("a datagram with no quarter ID is refused", WT_ERR_PROTOCOL,
                     wt_webtransport_datagram_parse(too_short, sizeof(too_short), &quarter, &parsed,
                                                    &parsed_length, &error));
    WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  }
  WT_EXPECT_STATUS("and an empty one is too", WT_ERR_PROTOCOL,
                   wt_webtransport_datagram_parse(NULL, 0U, &quarter, &parsed, &parsed_length,
                                                  &error));
}

int main(void) {
  test_session_id_shape();
  test_stream_prefix();
  test_datagrams();
  WT_TEST_MAIN_END("wt_webtransport_framing");
}
