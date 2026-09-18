/* QUIC transport parameters (RFC 9000 section 18).
 *
 * The parser's job is narrow on purpose: framing and duplicates. RFC 9000
 * section 7.4.2 requires an unknown parameter to be ignored, so a parser that
 * refused one would break the extension, and section 7.4 makes a duplicate a
 * TRANSPORT_PARAMETER_ERROR, so a parser that accepted one would accept a peer
 * that cannot decide what it means. The value rules of section 18.2 are a
 * separate check, and each of them is tested here against the boundary the RFC
 * names rather than against a value that happens to be wrong.
 */

#include "wt_test.h"

#include "test_quic_transport_parameters_limits_support.h"
#include "webtransport/quic/transport_parameters.h"

/* The parameters an endpoint MUST send (RFC 9000 section 7.3), and the omission a third-party peer named.
 *
 * aioquic closed this client's first interop handshake with `0x8 TRANSPORT_PARAMETER_ERROR:
 * initial_source_connection_id does not match`, because the parameter was absent: two callers built the block by
 * hand and both left it out, and the C99 peer accepted it because it shares the omission (WT-141). These cases
 * are what a peer compares. */
static void test_build_sends_the_mandatory_connection_ids(void) {
  static const uint8_t client_source[] = {0x11U, 0x22U, 0x33U, 0x44U};
  static const uint8_t server_source[] = {0xaaU, 0xbbU};
  wt_quic_transport_parameters_t params;
  uint8_t encoded[256];
  wt_writer_t w = wt_writer_init(encoded, sizeof(encoded));
  wt_status_t status;

  /* A client: its own Source Connection ID, and nothing about a destination it did not choose. */
  WT_EXPECT_OK("a client's parameters build",
               wt_quic_transport_parameters_build(&params, 0, client_source, sizeof(client_source),
                                                  NULL, 0U, 0, NULL, 0U));
  WT_EXPECT_OK("and encode", wt_quic_transport_parameters_encode(&w, &params));
  {
    wt_quic_transport_parameters_t read_back;
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    WT_EXPECT_OK("and decode again", wt_quic_transport_parameters_decode(
                                         encoded, wt_writer_offset(&w), &read_back, &error));
    WT_EXPECT_OK("with initial_source_connection_id present",
                 wt_quic_transport_parameters_get(
                     &read_back, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &value, &value_length));
    WT_EXPECT_U64("of the source connection ID's length", (uint64_t)sizeof(client_source),
                  (uint64_t)value_length);
    WT_EXPECT_BYTES("and its bytes", client_source, value, sizeof(client_source));
    WT_EXPECT_STATUS("and no original_destination_connection_id, which a client must not send",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_get(&read_back,
                                                      WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
                                                      &value, &value_length));
    /* Every limit this endpoint advertises, read back from the wire. `initial_max_stream_data_bidi_remote` is
     * the one a client got wrong: it is the credit for data the PEER sends on streams this endpoint opened, so
     * omitting it advertises zero and a conforming peer may answer nothing at all -- which is the whole session
     * (WT-145). The other two are here because a set is only right as a set. */
    {
      uint64_t limit = 0U;
      WT_EXPECT_OK("with initial_max_stream_data_bidi_remote present",
                   wt_quic_transport_parameters_integer(
                       &read_back, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, &limit));
      WT_EXPECT_TRUE("and non-zero, because zero is the value a session cannot work with",
                     limit > 0U);
      WT_EXPECT_OK("with initial_max_stream_data_uni present",
                   wt_quic_transport_parameters_integer(
                       &read_back, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, &limit));
      WT_EXPECT_TRUE("and non-zero", limit > 0U);
      WT_EXPECT_OK("with max_datagram_frame_size present",
                   wt_quic_transport_parameters_integer(
                       &read_back, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, &limit));
      WT_EXPECT_TRUE("and non-zero, because draft-16 section 3.1 requires QUIC datagram support",
                     limit > 0U);
      /* And the reliable-stream-reset flag draft-16 section 3.1 requires of BOTH roles, which is EMPTY: it
       * advertises the extension rather than configuring it. */
      WT_EXPECT_OK("with the reset_stream_at parameter present",
                   wt_quic_transport_parameters_get(&read_back, WT_QUIC_TP_RESET_STREAM_AT, &value,
                                                    &value_length));
      WT_EXPECT_U64("whose value is empty", 0U, (uint64_t)value_length);
    }
  }

  /* A server: both parameters, and the second is the ID the CLIENT addressed it by, not its own. */
  {
    uint8_t encoded_server[256];
    wt_writer_t server_writer = wt_writer_init(encoded_server, sizeof(encoded_server));
    wt_quic_transport_parameters_t read_back;
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    WT_EXPECT_OK("a server's parameters build",
                 wt_quic_transport_parameters_build(&params, 1, server_source,
                                                    sizeof(server_source), client_source,
                                                    sizeof(client_source), 0, NULL, 0U));
    WT_EXPECT_OK("and encode", wt_quic_transport_parameters_encode(&server_writer, &params));
    WT_EXPECT_OK("and decode again",
                 wt_quic_transport_parameters_decode(
                     encoded_server, wt_writer_offset(&server_writer), &read_back, &error));
    WT_EXPECT_OK("with initial_source_connection_id",
                 wt_quic_transport_parameters_get(
                     &read_back, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &value, &value_length));
    WT_EXPECT_BYTES("set to the server's own", server_source, value, sizeof(server_source));
    WT_EXPECT_OK("and original_destination_connection_id",
                 wt_quic_transport_parameters_get(&read_back,
                                                  WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
                                                  &value, &value_length));
    WT_EXPECT_BYTES("set to the client's", client_source, value, sizeof(client_source));
  }

  /* A server that cannot say which connection ID it was addressed by has a caller bug, refused here rather than
   * sent as a parameter list a peer would close over. */
  status = wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source),
                                              NULL, 0U, 0, NULL, 0U);
  WT_EXPECT_STATUS("a server without an original destination is refused", WT_ERR_INVALID_ARGUMENT,
                   status);
  status = wt_quic_transport_parameters_build(&params, 0, NULL, 0U, NULL, 0U, 0, NULL, 0U);
  WT_EXPECT_STATUS("and a list with no source connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                   status);
}

/* WT-168: the parameter a server sends ONLY when it sent a Retry (RFC 9000 section 7.3), and the two opposite
 * mistakes the builder refuses instead of sending. Both directions are close errors a checking peer closes on:
 * a server that retried and omits the parameter, and a server that did not retry and sends one anyway. */
static void test_a_retry_is_named_only_when_one_was_sent(void) {
  static const uint8_t client_source[] = {0x11U, 0x22U, 0x33U, 0x44U};
  static const uint8_t server_source[] = {0xaaU, 0xbbU};
  static const uint8_t retry_source[] = {0xccU, 0xddU, 0xeeU};
  wt_quic_transport_parameters_t params;
  uint8_t retried_encoded[256];
  wt_writer_t retried_writer = wt_writer_init(retried_encoded, sizeof(retried_encoded));
  wt_status_t status;

  WT_EXPECT_OK("a server that retried builds",
               wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source),
                                                  client_source, sizeof(client_source), 1,
                                                  retry_source, sizeof(retry_source)));
  WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&retried_writer, &params));
  {
    wt_quic_transport_parameters_t read_back;
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    WT_EXPECT_OK("and decodes again",
                 wt_quic_transport_parameters_decode(
                     retried_encoded, wt_writer_offset(&retried_writer), &read_back, &error));
    WT_EXPECT_OK("with retry_source_connection_id",
                 wt_quic_transport_parameters_get(&read_back, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID,
                                                  &value, &value_length));
    WT_EXPECT_BYTES("set to the Retry's Source Connection ID", retry_source, value,
                    sizeof(retry_source));
    /* And the TWO parameters that were already there are untouched by the third. */
    WT_EXPECT_OK("while original_destination_connection_id is still the client's",
                 wt_quic_transport_parameters_get(&read_back,
                                                  WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
                                                  &value, &value_length));
    WT_EXPECT_BYTES("byte for byte", client_source, value, sizeof(client_source));
  }

  /* A Retry the parameters do not name. */
  status = wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source),
                                              client_source, sizeof(client_source), 1, NULL, 0U);
  WT_EXPECT_STATUS("a Retry with no source connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                   status);
  /* And a name for a Retry that was never sent. */
  status = wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source),
                                              client_source, sizeof(client_source), 0, retry_source,
                                              sizeof(retry_source));
  WT_EXPECT_STATUS("a retry source without a Retry is refused too", WT_ERR_INVALID_ARGUMENT,
                   status);
  status = wt_quic_transport_parameters_build(&params, 0, client_source, sizeof(client_source),
                                              NULL, 0U, 1, retry_source, sizeof(retry_source));
  WT_EXPECT_STATUS("and a client cannot name one at all", WT_ERR_INVALID_ARGUMENT, status);
}

/* F-04: the reliable-stream-reset extension's transport parameter is registered as 0x1d by
 * draft-ietf-quic-reliable-stream-reset-09 section 8.1, and draft-ietf-webtrans-http3-16 section 3.1 makes an
 * empty `reset_stream_at` a requirement of EVERY WebTransport endpoint. The pre-registration value this tree
 * advertised (0x17f7586d2cb570, a greased 8-byte varint) is not the identifier a conforming draft-16 peer
 * looks for, so the extension was never negotiated. The assertion is on the WIRE byte and not on the C
 * constant: a test that compared `WT_QUIC_TP_RESET_STREAM_AT` with itself would pass while the wire stayed
 * wrong. */
static void test_reset_stream_at_is_the_registered_identifier(void) {
  wt_quic_transport_parameters_t params;
  uint8_t encoded[16];
  wt_writer_t w = wt_writer_init(encoded, sizeof(encoded));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK(
      "the reliable-stream-reset parameter is added",
      wt_quic_transport_parameters_add_bytes(&params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U));
  WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&w, &params));
  /* The registered identifier is 0x1d, a one-byte varint, followed by the empty value's zero length. */
  WT_EXPECT_U64("to exactly two bytes", 2U, (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_BYTES("with 0x1d as the identifier on the wire", (const uint8_t *)"\x1d\x00", encoded,
                  2U);
}
int main(void) {
  test_build_sends_the_mandatory_connection_ids();
  test_a_retry_is_named_only_when_one_was_sent();
  test_reset_stream_at_is_the_registered_identifier();
  WT_TEST_MAIN_END("test_quic_transport_parameters");
}
