/* The HTTP/3 GOAWAY frame (RFC 9114 sections 7.2.6 and 5.2).
 *
 * The frame is one varint, so the tests are about what the identifier MEANS: it
 * is a stream ID from a server and a push ID from a client, it may not grow
 * between frames, requests at or above it are rejected, and no new request may be
 * started after it arrives. The graceful-shutdown pattern -- the maximum first,
 * then what was really processed -- is the case that must keep working, because
 * the monotonic rule exists to make it usable. */

#include "wt_test.h"

#include "webtransport/http3/goaway.h"
#include "webtransport/quic/varint.h"

static void test_payload_round_trip(void) {
  static const uint64_t identifiers[] = {0U, 4U, 1024U, WT_HTTP3_GOAWAY_SERVER_MAXIMUM,
                                         WT_HTTP3_GOAWAY_CLIENT_MAXIMUM};
  uint8_t payload[16];
  size_t i;

  for (i = 0U; i < sizeof(identifiers) / sizeof(identifiers[0]); i++) {
    wt_writer_t w = wt_writer_init(payload, sizeof(payload));
    uint64_t decoded = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    WT_EXPECT_OK("the payload encodes", wt_http3_goaway_encode_payload(&w, identifiers[i]));
    WT_EXPECT_OK("and decodes",
                 wt_http3_goaway_decode_payload(payload, wt_writer_offset(&w), &decoded, &error));
    WT_EXPECT_U64("with the same identifier", identifiers[i], decoded);
  }
}

static void test_payload_errors(void) {
  static const uint8_t two_varints[2] = {0x04U, 0x08U};
  uint8_t payload[4];
  uint64_t decoded = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));

  WT_EXPECT_STATUS("an empty payload is refused", WT_ERR_TRUNCATED,
                   wt_http3_goaway_decode_payload(NULL, 0U, &decoded, &error));
  WT_EXPECT_U64("as a frame error", WT_HTTP3_FRAME_ERROR, (uint64_t)error);

  /* A varint whose continuation runs off the end. */
  payload[0] = 0x40U;
  WT_EXPECT_STATUS("a truncated varint is refused", WT_ERR_TRUNCATED,
                   wt_http3_goaway_decode_payload(payload, 1U, &decoded, &error));
  WT_EXPECT_U64("as a frame error", WT_HTTP3_FRAME_ERROR, (uint64_t)error);

  /* The frame carries one field. A second varint is a frame this endpoint cannot
   * interpret, and reading the first and ignoring the rest would accept it. */
  WT_EXPECT_STATUS("a second field is refused", WT_ERR_PROTOCOL,
                   wt_http3_goaway_decode_payload(two_varints, sizeof(two_varints), &decoded,
                                                  &error));
  WT_EXPECT_U64("as a frame error", WT_HTTP3_FRAME_ERROR, (uint64_t)error);

  /* And so is a trailing byte after a complete varint. */
  (void)wt_quic_writer_varint(&w, 0U);
  payload[wt_writer_offset(&w)] = 0x00U;
  WT_EXPECT_STATUS("trailing bytes are refused", WT_ERR_PROTOCOL,
                   wt_http3_goaway_decode_payload(payload, wt_writer_offset(&w) + 1U, &decoded,
                                                  &error));
  WT_EXPECT_U64("as a frame error", WT_HTTP3_FRAME_ERROR, (uint64_t)error);
}

static void test_server_identifier_must_be_a_request_stream(void) {
  static const uint64_t valid[] = {0U, 4U, 8U, WT_HTTP3_GOAWAY_SERVER_MAXIMUM};
  static const uint64_t invalid[] = {1U, 2U, 3U, 5U, WT_HTTP3_GOAWAY_CLIENT_MAXIMUM};
  size_t i;

  for (i = 0U; i < sizeof(valid) / sizeof(valid[0]); i++) {
    wt_http3_goaway_t goaway;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    wt_http3_goaway_init(&goaway);
    WT_EXPECT_OK("a client-initiated bidirectional stream ID is accepted",
                 wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, valid[i], &error));
    WT_EXPECT_U64("and recorded", valid[i], goaway.identifier);
  }

  for (i = 0U; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    wt_http3_goaway_t goaway;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    wt_http3_goaway_init(&goaway);
    WT_EXPECT_STATUS("any other stream type is refused", WT_ERR_PROTOCOL,
                     wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, invalid[i], &error));
    WT_EXPECT_U64("as an ID error", WT_HTTP3_ID_ERROR, (uint64_t)error);
    WT_EXPECT_INT("and nothing is recorded", 0, goaway.received);
  }

  /* A client's GOAWAY carries a push ID, which is a plain varint: no stream type
   * to check, and the maximum is the push maximum rather than the stream one. */
  {
    wt_http3_goaway_t goaway;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    wt_http3_goaway_init(&goaway);
    WT_EXPECT_OK("a client's push ID is accepted",
                 wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_CLIENT, 3U, &error));
    WT_EXPECT_U64("and recorded", 3U, goaway.identifier);
    WT_EXPECT_INT("with the client as its sender", (int)WT_HTTP3_ROLE_CLIENT, (int)goaway.sender);
  }
}

static void test_the_identifier_never_grows(void) {
  wt_http3_goaway_t goaway;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_goaway_init(&goaway);
  /* The graceful shutdown: the maximum first, so the peer stops starting
   * requests, then what was really processed. */
  WT_EXPECT_OK("the maximum is announced",
               wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER,
                                           wt_http3_goaway_maximum_identifier(WT_HTTP3_ROLE_SERVER),
                                           &error));
  WT_EXPECT_U64("recorded", WT_HTTP3_GOAWAY_SERVER_MAXIMUM, goaway.identifier);
  WT_EXPECT_OK("and a lower identifier follows it",
               wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 12U, &error));
  WT_EXPECT_U64("which becomes the effective one", 12U, goaway.identifier);
  WT_EXPECT_OK("repeating the same identifier is allowed",
               wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 12U, &error));

  WT_EXPECT_STATUS("but a larger one is refused", WT_ERR_PROTOCOL,
                   wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 16U, &error));
  WT_EXPECT_U64("as an ID error", WT_HTTP3_ID_ERROR, (uint64_t)error);
  WT_EXPECT_U64("with the effective identifier unchanged", 12U, goaway.identifier);

  /* A client's GOAWAY is monotonic in the same way, over push IDs. */
  wt_http3_goaway_init(&goaway);
  WT_EXPECT_OK("a client announces the push maximum",
               wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_CLIENT,
                                           wt_http3_goaway_maximum_identifier(WT_HTTP3_ROLE_CLIENT),
                                           &error));
  WT_EXPECT_OK("then what it processed",
               wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_CLIENT, 2U, &error));
  WT_EXPECT_STATUS("and may not grow it again", WT_ERR_PROTOCOL,
                   wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_CLIENT, 3U, &error));
  WT_EXPECT_U64("as an ID error", WT_HTTP3_ID_ERROR, (uint64_t)error);
}

static void test_rejection_and_new_requests(void) {
  wt_http3_goaway_t goaway;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_goaway_init(&goaway);
  WT_EXPECT_INT("no GOAWAY rejects nothing", 0, wt_http3_goaway_rejects_stream(&goaway, 1000U));
  WT_EXPECT_INT("and new requests are allowed", 1, wt_http3_goaway_allows_new_requests(&goaway));

  WT_EXPECT_OK("a GOAWAY at stream 8",
               wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 8U, &error));
  WT_EXPECT_INT("stops new requests", 0, wt_http3_goaway_allows_new_requests(&goaway));
  WT_EXPECT_INT("leaves the streams below it alone", 0, wt_http3_goaway_rejects_stream(&goaway, 0U));
  WT_EXPECT_INT("including the one just below", 0,
                wt_http3_goaway_rejects_stream(&goaway, 4U));
  WT_EXPECT_INT("and rejects the identifier itself", 1,
                wt_http3_goaway_rejects_stream(&goaway, 8U));
  WT_EXPECT_INT("and everything above", 1, wt_http3_goaway_rejects_stream(&goaway, 12U));

  /* An identifier of zero is the "nothing was processed" case, which rejects
   * every request rather than none. */
  wt_http3_goaway_init(&goaway);
  WT_EXPECT_OK("a GOAWAY at zero", wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 0U,
                                                              &error));
  WT_EXPECT_INT("rejects the first stream", 1, wt_http3_goaway_rejects_stream(&goaway, 0U));
}

int main(void) {
  test_payload_round_trip();
  test_payload_errors();
  test_server_identifier_must_be_a_request_stream();
  test_the_identifier_never_grows();
  test_rejection_and_new_requests();
  WT_TEST_MAIN_END("wt_http3_goaway");
}
