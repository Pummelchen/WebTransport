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
               wt_quic_transport_parameters_build(&params, 0, client_source, sizeof(client_source), NULL, 0U,
                                                  0, NULL, 0U));
  WT_EXPECT_OK("and encode", wt_quic_transport_parameters_encode(&w, &params));
  {
    wt_quic_transport_parameters_t read_back;
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    WT_EXPECT_OK("and decode again",
                 wt_quic_transport_parameters_decode(encoded, wt_writer_offset(&w), &read_back, &error));
    WT_EXPECT_OK("with initial_source_connection_id present",
                 wt_quic_transport_parameters_get(&read_back, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &value,
                                                  &value_length));
    WT_EXPECT_U64("of the source connection ID's length", (uint64_t)sizeof(client_source),
                  (uint64_t)value_length);
    WT_EXPECT_BYTES("and its bytes", client_source, value, sizeof(client_source));
    WT_EXPECT_STATUS("and no original_destination_connection_id, which a client must not send",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_get(&read_back,
                                                      WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &value,
                                                      &value_length));
    /* Every limit this endpoint advertises, read back from the wire. `initial_max_stream_data_bidi_remote` is
     * the one a client got wrong: it is the credit for data the PEER sends on streams this endpoint opened, so
     * omitting it advertises zero and a conforming peer may answer nothing at all -- which is the whole session
     * (WT-145). The other two are here because a set is only right as a set. */
    {
      uint64_t limit = 0U;
      WT_EXPECT_OK("with initial_max_stream_data_bidi_remote present",
                   wt_quic_transport_parameters_integer(&read_back,
                                                        WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, &limit));
      WT_EXPECT_TRUE("and non-zero, because zero is the value a session cannot work with", limit > 0U);
      WT_EXPECT_OK("with initial_max_stream_data_uni present",
                   wt_quic_transport_parameters_integer(&read_back, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                                                        &limit));
      WT_EXPECT_TRUE("and non-zero", limit > 0U);
      WT_EXPECT_OK("with max_datagram_frame_size present",
                   wt_quic_transport_parameters_integer(&read_back, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, &limit));
      WT_EXPECT_TRUE("and non-zero, because draft-16 section 3.1 requires QUIC datagram support", limit > 0U);
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
                 wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source),
                                                    client_source, sizeof(client_source), 0, NULL, 0U));
    WT_EXPECT_OK("and encode", wt_quic_transport_parameters_encode(&server_writer, &params));
    WT_EXPECT_OK("and decode again",
                 wt_quic_transport_parameters_decode(encoded_server, wt_writer_offset(&server_writer),
                                                     &read_back, &error));
    WT_EXPECT_OK("with initial_source_connection_id",
                 wt_quic_transport_parameters_get(&read_back, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &value,
                                                  &value_length));
    WT_EXPECT_BYTES("set to the server's own", server_source, value, sizeof(server_source));
    WT_EXPECT_OK("and original_destination_connection_id",
                 wt_quic_transport_parameters_get(&read_back,
                                                  WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &value,
                                                  &value_length));
    WT_EXPECT_BYTES("set to the client's", client_source, value, sizeof(client_source));
  }

  /* A server that cannot say which connection ID it was addressed by has a caller bug, refused here rather than
   * sent as a parameter list a peer would close over. */
  status = wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source), NULL, 0U, 0,
                                              NULL, 0U);
  WT_EXPECT_STATUS("a server without an original destination is refused", WT_ERR_INVALID_ARGUMENT, status);
  status = wt_quic_transport_parameters_build(&params, 0, NULL, 0U, NULL, 0U, 0, NULL, 0U);
  WT_EXPECT_STATUS("and a list with no source connection ID is refused", WT_ERR_INVALID_ARGUMENT, status);
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
                                                  client_source, sizeof(client_source), 1, retry_source,
                                                  sizeof(retry_source)));
  WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&retried_writer, &params));
  {
    wt_quic_transport_parameters_t read_back;
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    WT_EXPECT_OK("and decodes again",
                 wt_quic_transport_parameters_decode(retried_encoded, wt_writer_offset(&retried_writer),
                                                     &read_back, &error));
    WT_EXPECT_OK("with retry_source_connection_id",
                 wt_quic_transport_parameters_get(&read_back, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID, &value,
                                                  &value_length));
    WT_EXPECT_BYTES("set to the Retry's Source Connection ID", retry_source, value, sizeof(retry_source));
    /* And the TWO parameters that were already there are untouched by the third. */
    WT_EXPECT_OK("while original_destination_connection_id is still the client's",
                 wt_quic_transport_parameters_get(&read_back,
                                                  WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &value,
                                                  &value_length));
    WT_EXPECT_BYTES("byte for byte", client_source, value, sizeof(client_source));
  }

  /* A Retry the parameters do not name. */
  status = wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source), client_source,
                                              sizeof(client_source), 1, NULL, 0U);
  WT_EXPECT_STATUS("a Retry with no source connection ID is refused", WT_ERR_INVALID_ARGUMENT, status);
  /* And a name for a Retry that was never sent. */
  status = wt_quic_transport_parameters_build(&params, 1, server_source, sizeof(server_source), client_source,
                                              sizeof(client_source), 0, retry_source, sizeof(retry_source));
  WT_EXPECT_STATUS("a retry source without a Retry is refused too", WT_ERR_INVALID_ARGUMENT, status);
  status = wt_quic_transport_parameters_build(&params, 0, client_source, sizeof(client_source), NULL, 0U, 1,
                                              retry_source, sizeof(retry_source));
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
  WT_EXPECT_OK("the reliable-stream-reset parameter is added",
               wt_quic_transport_parameters_add_bytes(&params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U));
  WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&w, &params));
  /* The registered identifier is 0x1d, a one-byte varint, followed by the empty value's zero length. */
  WT_EXPECT_U64("to exactly two bytes", 2U, (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_BYTES("with 0x1d as the identifier on the wire", (const uint8_t *)"\x1d\x00", encoded, 2U);
}

/* F-05: two RFC 9000 section 18.2 rules the check did not have. Section 4.6: a max_streams transport
 * parameter above 2^60 MUST be closed with TRANSPORT_PARAMETER_ERROR ("2^60" itself is allowed; only greater
 * is an error). Section 18.2: stateless_reset_token is valid only for a server, so a server MUST treat receipt
 * from a client as TRANSPORT_PARAMETER_ERROR -- which is why the check now takes the sending role. */
static void test_stream_limits_and_a_clients_reset_token(void) {
  wt_quic_transport_parameters_t check;
  static const uint8_t sixteen[16] = {0};
  const uint64_t over_two_to_sixty = (UINT64_C(1) << 60) + 1U;
  wt_quic_error_t error = 0U;
  uint64_t offender = 0U;

  /* 2^60 is the boundary and is legal; one above it is not, in either direction. */
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                                 UINT64_C(1) << 60);
  WT_EXPECT_STATUS("initial_max_streams_bidi of 2^60 is accepted", WT_OK,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                                 over_two_to_sixty);
  error = 0U;
  offender = 0U;
  WT_EXPECT_STATUS("initial_max_streams_bidi above 2^60 is refused", WT_ERR_PROTOCOL,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  WT_EXPECT_U64("  as a transport parameter error", WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
  WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, offender);

  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                                                 UINT64_C(1) << 60);
  WT_EXPECT_STATUS("initial_max_streams_uni of 2^60 is accepted", WT_OK,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                                                 over_two_to_sixty);
  error = 0U;
  offender = 0U;
  WT_EXPECT_STATUS("initial_max_streams_uni above 2^60 is refused", WT_ERR_PROTOCOL,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, offender);

  /* A sixteen-byte token is well formed either way; only a CLIENT sending one is the error. */
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_bytes(&check, WT_QUIC_TP_STATELESS_RESET_TOKEN, sixteen,
                                               sizeof(sixteen));
  WT_EXPECT_STATUS("a server's stateless_reset_token is accepted", WT_OK,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  error = 0U;
  offender = 0U;
  WT_EXPECT_STATUS("a client's stateless_reset_token is refused", WT_ERR_PROTOCOL,
                   wt_quic_transport_parameters_check(&check, 1, &error, &offender));
  WT_EXPECT_U64("  as a transport parameter error", WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
  WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_STATELESS_RESET_TOKEN, offender);
}

int main(void) {
  wt_quic_transport_parameters_t params;
  wt_quic_error_t error = 0U;
  uint64_t offender = 0U;
  uint64_t value = 0U;
  size_t length = 0U;
  const uint8_t *found;

  /* A list built and encoded, then parsed back. The integer values are encoded
   * into the structure's own storage, so nothing here needs to stay alive. */
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_U64("a new list is empty", 0U, (uint64_t)params.count);
  WT_EXPECT_INT("and sorted", 1, params.sorted);
  WT_EXPECT_STATUS("initial_max_data", WT_OK,
                   wt_quic_transport_parameters_add_integer(
                       &params, WT_QUIC_TP_INITIAL_MAX_DATA, 1048576U));
  WT_EXPECT_STATUS("max_idle_timeout", WT_OK,
                   wt_quic_transport_parameters_add_integer(
                       &params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 30000U));
  WT_EXPECT_STATUS("max_udp_payload_size", WT_OK,
                   wt_quic_transport_parameters_add_integer(
                       &params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1472U));
  WT_EXPECT_STATUS("active_connection_id_limit", WT_OK,
                   wt_quic_transport_parameters_add_integer(
                       &params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 4U));
  WT_EXPECT_U64("four parameters", 4U, (uint64_t)params.count);
  /* The list is kept sorted by identifier, which is what makes the lookup a
   * binary search and a duplicate findable in one pass. */
  WT_EXPECT_TRUE("the list is sorted", params.entries[0].id < params.entries[1].id);
  WT_EXPECT_U64("the first is the lowest identifier",
                WT_QUIC_TP_MAX_IDLE_TIMEOUT, params.entries[0].id);

  /* A duplicate is refused when adding and again when encoding. */
  WT_EXPECT_STATUS("a duplicate identifier is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_transport_parameters_add_integer(
                       &params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 1U));

  /* The values are found by identifier. */
  WT_EXPECT_STATUS("initial_max_data reads back", WT_OK,
                   wt_quic_transport_parameters_integer(
                       &params, WT_QUIC_TP_INITIAL_MAX_DATA, &value));
  WT_EXPECT_U64("with its value", 1048576U, value);
  WT_EXPECT_STATUS("max_udp_payload_size reads back", WT_OK,
                   wt_quic_transport_parameters_integer(
                       &params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, &value));
  WT_EXPECT_U64("with its value", 1472U, value);
  /* Absent is not zero. */
  WT_EXPECT_STATUS("an absent parameter is not zero",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_transport_parameters_integer(
                       &params, WT_QUIC_TP_STATELESS_RESET_TOKEN, &value));
  found = NULL;
  WT_EXPECT_STATUS("a present parameter is found", WT_OK,
                   wt_quic_transport_parameters_get(
                       &params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, &found, &length));
  WT_EXPECT_TRUE("with a value", found != NULL);
  /* 30000 needs a four-byte varint, so the value is four bytes. */
  WT_EXPECT_U64("and its length", 4U, (uint64_t)length);
  WT_EXPECT_STATUS("an absent parameter is not found",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_transport_parameters_get(
                       &params, WT_QUIC_TP_STATELESS_RESET_TOKEN, &found,
                       &length));
  /* Presence is the status: a parameter with an empty value is present and its
   * value view may be NULL, which is not the same as being absent. */
  {
    wt_quic_transport_parameters_t empty;
    wt_quic_transport_parameters_init(&empty);
    (void)wt_quic_transport_parameters_add_bytes(
        &empty, WT_QUIC_TP_DISABLE_ACTIVE_MIGRATION, NULL, 0U);
    found = (const uint8_t *)"x";
    length = 99U;
    WT_EXPECT_STATUS("an empty-valued parameter is present", WT_OK,
                     wt_quic_transport_parameters_get(
                         &empty, WT_QUIC_TP_DISABLE_ACTIVE_MIGRATION, &found,
                         &length));
    WT_EXPECT_U64("with a zero length", 0U, (uint64_t)length);
    WT_EXPECT_TRUE("and a null value view", found == NULL);
  }

  /* Encode and parse back. */
  {
    uint8_t buffer[256];
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_quic_transport_parameters_t parsed;
    WT_EXPECT_STATUS("the list encodes", WT_OK,
                     wt_quic_transport_parameters_encode(&w, &params));
    WT_EXPECT_TRUE("to something", wt_writer_offset(&w) > 0U);
    WT_EXPECT_STATUS("and parses back", WT_OK,
                     wt_quic_transport_parameters_decode(
                         buffer, wt_writer_offset(&w), &parsed, &error));
    WT_EXPECT_U64("with the same count", (uint64_t)params.count,
                  (uint64_t)parsed.count);
    WT_EXPECT_INT("and sorted", 1, parsed.sorted);
    WT_EXPECT_STATUS("initial_max_data survives", WT_OK,
                     wt_quic_transport_parameters_integer(
                         &parsed, WT_QUIC_TP_INITIAL_MAX_DATA, &value));
    WT_EXPECT_U64("with its value", 1048576U, value);
    WT_EXPECT_STATUS("max_idle_timeout survives", WT_OK,
                     wt_quic_transport_parameters_integer(
                         &parsed, WT_QUIC_TP_MAX_IDLE_TIMEOUT, &value));
    WT_EXPECT_U64("with its value", 30000U, value);

    /* The bytes are the encoding the RFC describes: an identifier varint, a
     * length varint and the value. The lowest identifier in this list is
     * max_idle_timeout (1) with 30000, which is a four-byte varint. */
    WT_EXPECT_BYTES("the encoding starts with the lowest identifier",
                    (const uint8_t *)"\x01\x04\x80\x00\x75\x30", buffer, 6U);
  }

  /* An unknown parameter is kept, not refused: RFC 9000 section 7.4.2. */
  {
    static const uint8_t unknown[] = {0x40U, 0x21U, 0x02U, 0xAAU, 0xBBU};
    wt_quic_transport_parameters_t parsed;
    WT_EXPECT_STATUS("an unknown parameter parses", WT_OK,
                     wt_quic_transport_parameters_decode(
                         unknown, sizeof(unknown), &parsed, &error));
    WT_EXPECT_U64("and is kept", 1U, (uint64_t)parsed.count);
    WT_EXPECT_U64("under its own identifier", 0x21U,
                  parsed.entries[0].id);
    WT_EXPECT_U64("with its value", 2U, (uint64_t)parsed.entries[0].length);
    WT_EXPECT_STR("with a name of unknown", "unknown",
                  wt_quic_transport_parameter_name(0x21U));
  }

  /* A duplicate identifier is a TRANSPORT_PARAMETER_ERROR (section 7.4). */
  {
    static const uint8_t duplicate[] = {0x01U, 0x01U, 0x0AU,
                                        0x01U, 0x01U, 0x0BU};
    wt_quic_transport_parameters_t parsed;
    error = 0U;
    WT_EXPECT_STATUS("a duplicate parameter is refused", WT_ERR_PROTOCOL,
                     wt_quic_transport_parameters_decode(
                         duplicate, sizeof(duplicate), &parsed, &error));
    WT_EXPECT_U64("  as a transport parameter error",
                  WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
  }

  /* A non-minimal length is refused: the same rule as a frame type. */
  {
    static const uint8_t padded_length[] = {0x01U, 0x80U, 0x00U, 0x00U,
                                            0x01U, 0x0AU};
    wt_quic_transport_parameters_t parsed;
    error = 0U;
    WT_EXPECT_STATUS("a non-minimal length is refused", WT_ERR_PROTOCOL,
                     wt_quic_transport_parameters_decode(
                         padded_length, sizeof(padded_length), &parsed,
                         &error));
  }

  /* Truncation, at the identifier, the length and the value. */
  {
    static const uint8_t cut_id[] = {0x80U};
    static const uint8_t cut_length[] = {0x01U, 0x40U};
    static const uint8_t cut_value[] = {0x01U, 0x04U, 0x0AU, 0x0BU};
    wt_quic_transport_parameters_t parsed;
    WT_EXPECT_STATUS("a truncated identifier is refused", WT_ERR_TRUNCATED,
                     wt_quic_transport_parameters_decode(
                         cut_id, sizeof(cut_id), &parsed, &error));
    WT_EXPECT_STATUS("a truncated length is refused", WT_ERR_TRUNCATED,
                     wt_quic_transport_parameters_decode(
                         cut_length, sizeof(cut_length), &parsed, &error));
    WT_EXPECT_STATUS("a truncated value is refused", WT_ERR_TRUNCATED,
                     wt_quic_transport_parameters_decode(
                         cut_value, sizeof(cut_value), &parsed, &error));
    WT_EXPECT_STATUS("a NULL list is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_decode(
                         cut_value, sizeof(cut_value), NULL, &error));
  }

  /* An empty list is valid: a peer may send no parameters at all, which is what
   * a client's first flight does when everything has a default. */
  {
    wt_quic_transport_parameters_t parsed;
    WT_EXPECT_STATUS("an empty list parses", WT_OK,
                     wt_quic_transport_parameters_decode(NULL, 0U, &parsed,
                                                         &error));
    WT_EXPECT_U64("with nothing in it", 0U, (uint64_t)parsed.count);
  }

  /* A list that arrives unsorted is scanned rather than refused: RFC 9000
   * section 18 does not order the parameters. */
  {
    static const uint8_t unsorted[] = {0x04U, 0x01U, 0x0AU,
                                       0x01U, 0x01U, 0x0BU};
    wt_quic_transport_parameters_t parsed;
    WT_EXPECT_STATUS("an unsorted list parses", WT_OK,
                     wt_quic_transport_parameters_decode(
                         unsorted, sizeof(unsorted), &parsed, &error));
    WT_EXPECT_INT("and is marked unsorted", 0, parsed.sorted);
    WT_EXPECT_STATUS("and its first parameter is found", WT_OK,
                     wt_quic_transport_parameters_integer(
                         &parsed, WT_QUIC_TP_INITIAL_MAX_DATA, &value));
    WT_EXPECT_U64("with its value", 10U, value);
    WT_EXPECT_STATUS("and its second", WT_OK,
                     wt_quic_transport_parameters_integer(
                         &parsed, WT_QUIC_TP_MAX_IDLE_TIMEOUT, &value));
    WT_EXPECT_U64("with its value", 11U, value);
    /* A duplicate in an unsorted list is still found. */
    {
      /* Unsorted and duplicated: identifiers 4, 1, 4. */
      static const uint8_t unsorted_duplicate[] = {0x04U, 0x01U, 0x0AU,
                                                   0x01U, 0x01U, 0x0BU,
                                                   0x04U, 0x01U, 0x0CU};
      error = 0U;
      WT_EXPECT_STATUS("a duplicate in an unsorted list is refused",
                       WT_ERR_PROTOCOL,
                       wt_quic_transport_parameters_decode(
                           unsorted_duplicate, sizeof(unsorted_duplicate),
                           &parsed, &error));
    }
  }

  /* An integer parameter whose value is not exactly one varint is refused BY
   * THE INTEGER ACCESSOR, not by the framing parser: a value of two bytes is
   * well framed, and whether those bytes are one varint is a question only the
   * caller that wanted an integer asks. */
  {
    static const uint8_t two_varints[] = {0x04U, 0x02U, 0x0AU, 0x0BU};
    static const uint8_t empty_value[] = {0x04U, 0x00U};
    wt_quic_transport_parameters_t parsed;
    WT_EXPECT_STATUS("a two-byte value is well framed", WT_OK,
                     wt_quic_transport_parameters_decode(
                         two_varints, sizeof(two_varints), &parsed, &error));
    WT_EXPECT_STATUS("but is not one integer", WT_ERR_TRUNCATED,
                     wt_quic_transport_parameters_integer(
                         &parsed, WT_QUIC_TP_INITIAL_MAX_DATA, &value));
    WT_EXPECT_STATUS("an empty value is well framed", WT_OK,
                     wt_quic_transport_parameters_decode(
                         empty_value, sizeof(empty_value), &parsed, &error));
    WT_EXPECT_STATUS("but is not an integer either", WT_ERR_TRUNCATED,
                     wt_quic_transport_parameters_integer(
                         &parsed, WT_QUIC_TP_INITIAL_MAX_DATA, &value));
  }

  /* The section 18.2 value rules, each at its boundary. */
  {
    wt_quic_transport_parameters_t check;
    /* max_udp_payload_size of 1199 is a violation; 1200 is not. */
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1199U);
    error = 0U;
    offender = 0U;
    WT_EXPECT_STATUS("max_udp_payload_size of 1199 is refused", WT_ERR_PROTOCOL,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));
    WT_EXPECT_U64("  as a transport parameter error",
                  WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
    WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                  offender);
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1200U);
    WT_EXPECT_STATUS("max_udp_payload_size of 1200 is accepted", WT_OK,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));

    /* reset_stream_at is a FLAG: one byte of value is a TRANSPORT_PARAMETER_ERROR, because a value nobody reads is
   * a negotiation nobody can rely on. The empty form is the only one that means "I support this extension". */
  {
    static const uint8_t k_not_empty[1] = {0x01U};
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_bytes(&check, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U);
    WT_EXPECT_STATUS("an empty reset_stream_at is accepted", WT_OK,
                     wt_quic_transport_parameters_check(&check, 0, &error, &offender));
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_bytes(&check, WT_QUIC_TP_RESET_STREAM_AT, k_not_empty,
                                                 sizeof(k_not_empty));
    error = 0U;
    offender = 0U;
    WT_EXPECT_STATUS("a non-empty reset_stream_at is refused", WT_ERR_PROTOCOL,
                     wt_quic_transport_parameters_check(&check, 0, &error, &offender));
    WT_EXPECT_U64("  as a transport parameter error", WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
    WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_RESET_STREAM_AT, offender);
  }

  /* ack_delay_exponent of 20 is fine, 21 is not. */
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_ACK_DELAY_EXPONENT, 20U);
    WT_EXPECT_STATUS("ack_delay_exponent of 20 is accepted", WT_OK,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_ACK_DELAY_EXPONENT, 21U);
    WT_EXPECT_STATUS("ack_delay_exponent of 21 is refused", WT_ERR_PROTOCOL,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));

    /* max_ack_delay of 2^14 - 1 is fine, 2^14 is not. */
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_MAX_ACK_DELAY, (UINT64_C(1) << 14) - 1U);
    WT_EXPECT_STATUS("max_ack_delay of 16383 is accepted", WT_OK,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_MAX_ACK_DELAY, UINT64_C(1) << 14);
    WT_EXPECT_STATUS("max_ack_delay of 16384 is refused", WT_ERR_PROTOCOL,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));

    /* active_connection_id_limit of 1 is a violation; 2 is the minimum. */
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 1U);
    WT_EXPECT_STATUS("active_connection_id_limit of 1 is refused",
                     WT_ERR_PROTOCOL,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 2U);
    WT_EXPECT_STATUS("active_connection_id_limit of 2 is accepted", WT_OK,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));

    /* A stateless reset token that is not sixteen bytes. */
    {
      static const uint8_t short_token[15] = {0};
      static const uint8_t exactly_sixteen[16] = {0};
      wt_quic_transport_parameters_init(&check);
      (void)wt_quic_transport_parameters_add_bytes(
          &check, WT_QUIC_TP_STATELESS_RESET_TOKEN, short_token,
          sizeof(short_token));
      WT_EXPECT_STATUS("a 15-byte stateless reset token is refused",
                       WT_ERR_PROTOCOL,
                       wt_quic_transport_parameters_check(&check, 0, &error,
                                                          &offender));
      wt_quic_transport_parameters_init(&check);
      (void)wt_quic_transport_parameters_add_bytes(
          &check, WT_QUIC_TP_STATELESS_RESET_TOKEN, exactly_sixteen,
          sizeof(exactly_sixteen));
      WT_EXPECT_STATUS("a 16-byte stateless reset token is accepted", WT_OK,
                       wt_quic_transport_parameters_check(&check, 0, &error,
                                                          &offender));
    }

    /* original_destination_connection_id is never empty and never above 20. */
    {
      static const uint8_t eight[8] = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
      static const uint8_t twenty_one[21] = {0};
      wt_quic_transport_parameters_init(&check);
      (void)wt_quic_transport_parameters_add_bytes(
          &check, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, NULL, 0U);
      WT_EXPECT_STATUS("an empty original destination ID is refused",
                       WT_ERR_PROTOCOL,
                       wt_quic_transport_parameters_check(&check, 0, &error,
                                                          &offender));
      WT_EXPECT_U64("  naming the parameter",
                    WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, offender);
      wt_quic_transport_parameters_init(&check);
      (void)wt_quic_transport_parameters_add_bytes(
          &check, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, twenty_one,
          sizeof(twenty_one));
      WT_EXPECT_STATUS("a 21-byte original destination ID is refused",
                       WT_ERR_PROTOCOL,
                       wt_quic_transport_parameters_check(&check, 0, &error,
                                                          &offender));
      wt_quic_transport_parameters_init(&check);
      (void)wt_quic_transport_parameters_add_bytes(
          &check, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, eight,
          sizeof(eight));
      WT_EXPECT_STATUS("an 8-byte original destination ID is accepted", WT_OK,
                       wt_quic_transport_parameters_check(&check, 0, &error,
                                                          &offender));
    }

    /* A source connection ID may be empty -- RFC 9000 section 7.3 allows a
     * zero-length connection ID -- but not above twenty. */
    {
      static const uint8_t twenty_one[21] = {0};
      wt_quic_transport_parameters_init(&check);
      (void)wt_quic_transport_parameters_add_bytes(
          &check, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, NULL, 0U);
      WT_EXPECT_STATUS("an empty initial source connection ID is accepted",
                       WT_OK,
                       wt_quic_transport_parameters_check(&check, 0, &error,
                                                          &offender));
      wt_quic_transport_parameters_init(&check);
      (void)wt_quic_transport_parameters_add_bytes(
          &check, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID, twenty_one,
          sizeof(twenty_one));
      WT_EXPECT_STATUS("a 21-byte retry source connection ID is refused",
                       WT_ERR_PROTOCOL,
                       wt_quic_transport_parameters_check(&check, 0, &error,
                                                          &offender));
    }

    /* max_datagram_frame_size of zero is NOT a violation: RFC 9221 section 3
     * defines zero as "DATAGRAM frames are not supported", which is what the
     * parameter's absence means too. */
    wt_quic_transport_parameters_init(&check);
    (void)wt_quic_transport_parameters_add_integer(
        &check, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 0U);
    WT_EXPECT_STATUS("max_datagram_frame_size of 0 is accepted", WT_OK,
                     wt_quic_transport_parameters_check(&check, 0, &error,
                                                        &offender));
  }

  /* The bounds: a full list, and a list with more parameters than the structure
   * holds is a protocol error rather than a silent truncation. */
  {
    wt_quic_transport_parameters_t full;
    size_t i;
    wt_quic_transport_parameters_init(&full);
    for (i = 0U; i < WT_QUIC_MAX_TRANSPORT_PARAMETERS; i++) {
      WT_EXPECT_STATUS("a parameter fits", WT_OK,
                       wt_quic_transport_parameters_add_integer(
                           &full, 0x100U + (uint64_t)i, (uint64_t)i));
    }
    WT_EXPECT_U64("the list is full", WT_QUIC_MAX_TRANSPORT_PARAMETERS,
                  (uint64_t)full.count);
    WT_EXPECT_STATUS("one more is refused", WT_ERR_LIMIT,
                     wt_quic_transport_parameters_add_integer(&full, 0x200U, 1U));
    {
      uint8_t buffer[1024];
      wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
      wt_quic_transport_parameters_t parsed;
      error = 0U;
      WT_EXPECT_STATUS("the full list encodes", WT_OK,
                       wt_quic_transport_parameters_encode(&w, &full));
      WT_EXPECT_STATUS("and parses", WT_OK,
                       wt_quic_transport_parameters_decode(
                           buffer, wt_writer_offset(&w), &parsed, &error));
      WT_EXPECT_U64("with every parameter", WT_QUIC_MAX_TRANSPORT_PARAMETERS,
                    (uint64_t)parsed.count);
    }
    /* One more than the bound on the wire: 33 single-byte parameters. */
    {
      uint8_t encoded[33U * 3U];
      wt_quic_transport_parameters_t parsed;
      size_t at = 0U;
      for (i = 0U; i < 33U; i++) {
        encoded[at++] = (uint8_t)(0x30U + i);
        encoded[at++] = 0x01U;
        encoded[at++] = 0x00U;
      }
      error = 0U;
      WT_EXPECT_STATUS("33 parameters are refused", WT_ERR_PROTOCOL,
                       wt_quic_transport_parameters_decode(encoded, at, &parsed,
                                                           &error));
      WT_EXPECT_U64("  as a transport parameter error",
                    WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
    }
  }

  /* Encoding refuses a duplicate, and a NULL argument. */
  {
    uint8_t buffer[64];
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_quic_transport_parameters_t duplicate;
    wt_quic_transport_parameters_init(&duplicate);
    (void)wt_quic_transport_parameters_add_integer(
        &duplicate, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 1U);
    /* Forge the duplicate the adder would have refused, so the encoder's own
     * check is what is tested. */
    duplicate.entries[1] = duplicate.entries[0];
    duplicate.count = 2U;
    WT_EXPECT_STATUS("the encoder refuses a duplicate", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_encode(&w, &duplicate));
    WT_EXPECT_STATUS("a NULL writer is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_encode(NULL, &params));
    WT_EXPECT_STATUS("a NULL list is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_encode(&w, NULL));
    WT_EXPECT_STATUS("a NULL list is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_get(NULL, 0U, NULL, NULL));
    WT_EXPECT_STATUS("an integer lookup with a NULL output is refused",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_integer(&params, 0U, NULL));
    WT_EXPECT_STATUS("a check with a NULL list is refused",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_check(NULL, 0, &error,
                                                        &offender));
    WT_EXPECT_STATUS("adding to a NULL list is refused",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_add_bytes(NULL, 1U, NULL, 0U));
    WT_EXPECT_STATUS("adding NULL bytes is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_transport_parameters_add_bytes(&params, 0x900U,
                                                            NULL, 4U));
  }

  /* The names. */
  WT_EXPECT_STR("max_idle_timeout", "max_idle_timeout",
                wt_quic_transport_parameter_name(WT_QUIC_TP_MAX_IDLE_TIMEOUT));
  WT_EXPECT_STR("max_udp_payload_size", "max_udp_payload_size",
                wt_quic_transport_parameter_name(
                    WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE));
  WT_EXPECT_STR("active_connection_id_limit", "active_connection_id_limit",
                wt_quic_transport_parameter_name(
                    WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT));
  WT_EXPECT_STR("max_datagram_frame_size", "max_datagram_frame_size",
                wt_quic_transport_parameter_name(
                    WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE));
  WT_EXPECT_STR("an unassigned identifier", "unknown",
                wt_quic_transport_parameter_name(0x4321U));

  test_build_sends_the_mandatory_connection_ids();
  test_a_retry_is_named_only_when_one_was_sent();
  test_reset_stream_at_is_the_registered_identifier();
  test_stream_limits_and_a_clients_reset_token();
  WT_TEST_MAIN_END("wt_quic_transport_parameters");
}
