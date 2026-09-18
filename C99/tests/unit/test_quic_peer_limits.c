/* The peer's transport parameters, turned into the limits this endpoint obeys.
 *
 * THE POINT OF THIS FILE IS THAT AN ABSENT PARAMETER AND A ZERO ONE ARE DIFFERENT FACTS. RFC 9000
 * section 18.2 gives several parameters a default that is not zero -- `max_udp_payload_size` is 65527,
 * `active_connection_id_limit` is 2 -- and gives the flow control limits an absent value of zero, which
 * happens to be the same number as sending zero but is a different statement. A parser that filled a
 * struct with zeros and read the parameters on top would get the second class right by accident and the
 * first class wrong, so the defaults are applied by name here and the test checks both.
 *
 * THE EFFECTIVE IDLE TIMEOUT IS THE SMALLER OF THE TWO, because RFC 9000 section 10.1 makes it the
 * minimum: a connection that enforced only its own would stay open after the peer had forgotten it, and
 * one that enforced only the peer's would outlive its own configuration. That is checked as arithmetic
 * through the connection's own timer rather than as a field.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/connection.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/writer.h"

/* A parameter list with every limit this runtime reads, and values that are all different from each
 * other so that a mix-up between two of them is visible. */
static size_t build_parameters(uint8_t *out, size_t capacity) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(out, capacity);

  wt_quic_transport_parameters_init(&params);
  /* The wire value is MILLISECONDS (RFC 9000 section 18.2) and the runtime's is MICROSECONDS, so this is 7000
   * ms = 7 s and the expectation below is 7,000,000. The same number on both sides of this test is what let the
   * missing conversion live: every local session read the same wrong value, so nothing disagreed until a peer
   * that advertises 30000 (quinn) had its 30 seconds taken for 30 milliseconds (WT-145). */
  WT_EXPECT_OK("max_idle_timeout", wt_quic_transport_parameters_add_integer(
                                       &params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 7000U));
  /* The reliable-stream-reset flag, which a peer signals by PRESENCE: its value is empty, and the limit it
   * produces is a boolean rather than a number. */
  WT_EXPECT_OK("reset_stream_at", wt_quic_transport_parameters_add_bytes(
                                      &params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U));
  WT_EXPECT_OK("max_udp_payload_size", wt_quic_transport_parameters_add_integer(
                                           &params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1452U));
  WT_EXPECT_OK("initial_max_data", wt_quic_transport_parameters_add_integer(
                                       &params, WT_QUIC_TP_INITIAL_MAX_DATA, 100000U));
  WT_EXPECT_OK("initial_max_stream_data_bidi_local",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 200000U));
  WT_EXPECT_OK("initial_max_stream_data_bidi_remote",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 300000U));
  WT_EXPECT_OK("initial_max_stream_data_uni",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 400000U));
  WT_EXPECT_OK("initial_max_streams_bidi", wt_quic_transport_parameters_add_integer(
                                               &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 7U));
  WT_EXPECT_OK("initial_max_streams_uni", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 9U));
  WT_EXPECT_OK("active_connection_id_limit",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 11U));
  WT_EXPECT_OK("max_datagram_frame_size", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 1200U));
  WT_EXPECT_OK("the list encodes", wt_quic_transport_parameters_encode(&w, &params));
  return wt_writer_offset(&w);
}

static void init_connection(wt_quic_connection_t *connection, uint64_t idle_timeout) {
  static const uint8_t id[4] = {1U, 2U, 3U, 4U};
  wt_quic_connection_config_t config;

  memset(&config, 0, sizeof(config));
  config.role = WT_QUIC_ROLE_CLIENT;
  config.version = WT_QUIC_VERSION_1;
  config.local_connection_id = id;
  config.local_connection_id_length = sizeof(id);
  config.peer_connection_id = id;
  config.peer_connection_id_length = sizeof(id);
  config.aead = WT_AEAD_AES_128_GCM;
  config.max_ack_delay = 25000U;
  config.local_max_ack_delay = 25000U;
  config.idle_timeout = idle_timeout;
  config.max_datagram_size = 1200U;
  WT_EXPECT_OK("the connection initialises", wt_quic_connection_init(connection, &config));
}

static void test_limits(void) {
  wt_quic_connection_t connection;
  const wt_quic_peer_limits_t *limits;
  uint8_t encoded[512];
  size_t length;

  init_connection(&connection, 30000000U);
  WT_EXPECT_INT("no parameters have been parsed yet", 0,
                wt_quic_connection_peer_limits(&connection)->set);

  length = build_parameters(encoded, sizeof(encoded));
  WT_EXPECT_TRUE("the parameter list has bytes", length > 0U);
  WT_EXPECT_OK("and the peer's parameters parse",
               wt_quic_connection_set_peer_parameters(&connection, encoded, length));

  limits = wt_quic_connection_peer_limits(&connection);
  WT_EXPECT_INT("now they have", 1, limits->set);
  WT_EXPECT_U64("the idle timeout, converted from the wire's milliseconds", 7000000U,
                limits->max_idle_timeout);
  WT_EXPECT_U64("the payload size", 1452U, limits->max_udp_payload_size);
  WT_EXPECT_U64("the connection's data limit", 100000U, limits->initial_max_data);
  WT_EXPECT_U64("the bidi-local stream limit", 200000U, limits->initial_max_stream_data_bidi_local);
  WT_EXPECT_U64("the bidi-remote stream limit", 300000U,
                limits->initial_max_stream_data_bidi_remote);
  WT_EXPECT_U64("the unidirectional stream limit", 400000U, limits->initial_max_stream_data_uni);
  WT_EXPECT_U64("the bidirectional stream count", 7U, limits->initial_max_streams_bidi);
  WT_EXPECT_U64("the unidirectional stream count", 9U, limits->initial_max_streams_uni);
  WT_EXPECT_U64("the connection ID limit", 11U, limits->active_connection_id_limit);
  WT_EXPECT_U64("and the datagram size", 1200U, limits->max_datagram_frame_size);
  WT_EXPECT_INT("and the reliable-stream-reset flag, which presence alone sets", 1,
                limits->reset_stream_at);

  /* A limit is what it is, not what the encoder happened to write: the same values through a real
   * round trip of the codec are what the test above read back. */
  {
    wt_quic_transport_parameters_t decoded;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    uint64_t value = 0U;
    WT_EXPECT_OK("the bytes decode",
                 wt_quic_transport_parameters_decode(encoded, length, &decoded, &error));
    WT_EXPECT_OK(
        "and max_idle_timeout reads back",
        wt_quic_transport_parameters_integer(&decoded, WT_QUIC_TP_MAX_IDLE_TIMEOUT, &value));
    WT_EXPECT_U64("as the value that was written, in the wire's own milliseconds", 7000U, value);
  }

  /* The peer's idle timeout is smaller than this endpoint's, so it is the one that applies: the
   * connection's own timer must arm for it. */
  {
    uint64_t delay = 0U;
    WT_EXPECT_OK("the idle timer is armed",
                 wt_quic_connection_next_timeout(&connection, 0U, &delay));
    WT_EXPECT_U64("for the smaller of the two idle timeouts", 7000000U, delay);
  }
}

/* A huge max_idle_timeout must saturate, not wrap. The wire value is a varint, so a peer may name a timeout far
 * past what a microsecond clock can hold; multiplying without a bound would turn "longer than any run" into a
 * few microseconds and close the connection at once -- the same failure the missing conversion caused, in the
 * other direction (WT-145). */
static void test_a_huge_idle_timeout_saturates(void) {
  wt_quic_connection_t connection;
  wt_quic_transport_parameters_t params;
  const wt_quic_peer_limits_t *limits;
  uint8_t encoded[64];
  wt_writer_t w = wt_writer_init(encoded, sizeof(encoded));
  size_t length;

  init_connection(&connection, 30000000U);
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a timeout past what microseconds can hold is named",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_MAX_IDLE_TIMEOUT,
                                                        ((UINT64_C(1) << 62) - 1U)));
  WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&w, &params));
  length = wt_writer_offset(&w);
  WT_EXPECT_OK("the connection reads it",
               wt_quic_connection_set_peer_parameters(&connection, encoded, length));
  limits = wt_quic_connection_peer_limits(&connection);
  WT_EXPECT_U64("and the limit saturates rather than wrapping", UINT64_MAX,
                limits->max_idle_timeout);
}

/* The defaults: an empty list grants no flow control, allows the two connection IDs, and leaves the
 * payload size at RFC 9000 section 18.2's 65527. */
static void test_defaults(void) {
  wt_quic_connection_t connection;
  const wt_quic_peer_limits_t *limits;
  uint8_t nothing[1] = {0U};
  uint64_t delay = 0U;

  init_connection(&connection, 30000000U);
  WT_EXPECT_OK("an empty parameter list is accepted",
               wt_quic_connection_set_peer_parameters(&connection, nothing, 0U));
  limits = wt_quic_connection_peer_limits(&connection);
  WT_EXPECT_INT("and is still a parsed list", 1, limits->set);
  WT_EXPECT_U64("with no data granted", 0U, limits->initial_max_data);
  WT_EXPECT_U64("no streams granted", 0U, limits->initial_max_streams_bidi);
  WT_EXPECT_U64("no datagrams allowed", 0U, limits->max_datagram_frame_size);
  WT_EXPECT_U64("the default payload size", WT_QUIC_DEFAULT_MAX_UDP_PAYLOAD_SIZE,
                limits->max_udp_payload_size);
  WT_EXPECT_U64("and the default connection ID limit", 2U, limits->active_connection_id_limit);
  /* The field holds the PEER's value, which is zero when it sent none; the effective timeout is the
   * minimum of the two, which is this endpoint's own here. */
  WT_EXPECT_U64("with no idle timeout from the peer", 0U, limits->max_idle_timeout);
  WT_EXPECT_INT(
      "and no reliable-stream-reset flag, which a peer that says nothing has not advertised", 0,
      limits->reset_stream_at);
  WT_EXPECT_OK("so its timer arms for its own",
               wt_quic_connection_next_timeout(&connection, 0U, &delay));
  WT_EXPECT_U64("which is thirty seconds", 30000000U, delay);

  /* The other way round: a peer that limits the idle timeout against a connection that does not. */
  init_connection(&connection, 0U);
  {
    wt_quic_transport_parameters_t params;
    wt_writer_t w;
    uint8_t encoded[64];
    size_t length;
    wt_quic_transport_parameters_init(&params);
    /* 4000 on the wire is four SECONDS (RFC 9000 section 18.2 counts milliseconds), which is 4,000,000
     * microseconds -- the number the assertion below wants, written as the peer would write it. */
    WT_EXPECT_OK("the peer's idle timeout", wt_quic_transport_parameters_add_integer(
                                                &params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 4000U));
    w = wt_writer_init(encoded, sizeof(encoded));
    WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&w, &params));
    length = wt_writer_offset(&w);
    WT_EXPECT_OK("and parses",
                 wt_quic_connection_set_peer_parameters(&connection, encoded, length));
  }
  WT_EXPECT_OK("the timer arms for the peer's",
               wt_quic_connection_next_timeout(&connection, 0U, &delay));
  WT_EXPECT_U64("which is four seconds", 4000000U, delay);
}

/* A list that breaks RFC 9000 section 18.2's rules is a connection error, not something to clamp. */
static void test_malformed(void) {
  wt_quic_connection_t connection;
  wt_quic_transport_parameters_t params;
  wt_writer_t w;
  uint8_t encoded[128];
  size_t length;

  init_connection(&connection, 30000000U);

  /* A max_udp_payload_size below 1200 is a TRANSPORT_PARAMETER_ERROR (section 18.2). */
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK(
      "a small payload size is encodable",
      wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1000U));
  w = wt_writer_init(encoded, sizeof(encoded));
  WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&w, &params));
  length = wt_writer_offset(&w);
  WT_EXPECT_STATUS("but is refused when parsed", WT_ERR_PROTOCOL,
                   wt_quic_connection_set_peer_parameters(&connection, encoded, length));
  WT_EXPECT_INT("leaving no limits behind", 0, wt_quic_connection_peer_limits(&connection)->set);

  /* A parameter whose length runs past the end of the extension is a truncation. */
  WT_EXPECT_STATUS("a truncated list is a truncation", WT_ERR_TRUNCATED,
                   wt_quic_connection_set_peer_parameters(&connection, encoded, length - 1U));

  /* The arguments. */
  WT_EXPECT_STATUS("a null connection is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_set_peer_parameters(NULL, encoded, length));
  WT_EXPECT_STATUS("and a null list with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_set_peer_parameters(&connection, NULL, 4U));
  WT_EXPECT_INT("and a null connection has no limits to read", 0,
                wt_quic_connection_peer_limits(NULL) == NULL ? 0 : 1);
}

int main(void) {
  test_limits();
  test_a_huge_idle_timeout_saturates();
  test_defaults();
  test_malformed();

  WT_TEST_MAIN_END("wt_quic_peer_limits");
}
