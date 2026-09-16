#include "test_http3_driver_internal.h"

void test_starting_our_own_streams(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_settings_t settings;
  uint8_t wire[256];
  uint8_t scratch[256];
  uint8_t read_scratch[256];
  size_t length;
  wt_writer_t w;
  wt_cursor_t cursor;
  wt_http3_frame_t frame;
  wt_http3_settings_t read_back;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t i;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);

  /* A SETTINGS frame with something in it, so the payload is not trivially empty. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a setting is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("and another",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 4096U));

  /* The control stream is the type prefix and then the frame: the reader finds both, which
   * is what makes this a stream rather than a bag of bytes. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("the control stream starts",
               wt_http3_driver_start_control(&driver, &settings, scratch, sizeof(scratch), &w));
  length = wt_writer_offset(&w);
  WT_EXPECT_TRUE("with bytes", length > 0U);
  WT_EXPECT_U64("the first byte being the control type", WT_HTTP3_STREAM_CONTROL, (uint64_t)wire[0]);

  cursor = wt_cursor_init(wire + 1U, length - 1U);
  WT_EXPECT_OK("and the rest decoding as a frame", wt_http3_frame_decode(&cursor, &frame, &error));
  WT_EXPECT_U64("of type SETTINGS", WT_HTTP3_FRAME_SETTINGS, frame.type);
  WT_EXPECT_OK("whose payload parses",
               wt_http3_settings_parse(frame.payload, frame.length, &read_back, &error));
  WT_EXPECT_U64("with the first setting back", 1U,
                wt_http3_settings_get(&read_back, WT_HTTP3_SETTING_WT_ENABLED, NULL));
  WT_EXPECT_U64("and the second", 4096U,
                wt_http3_settings_get(&read_back, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, NULL));
  WT_EXPECT_U64("with nothing left over", 0U, (uint64_t)wt_cursor_remaining(&cursor));

  /* A second control stream is the endpoint's one-per-connection rule, and it is refused
   * before any bytes are written. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_STATUS("a second control stream is refused", WT_ERR_STATE,
                   wt_http3_driver_start_control(&driver, &settings, scratch, sizeof(scratch), &w));
  WT_EXPECT_U64("with nothing written", 0U, (uint64_t)wt_writer_offset(&w));

  /* The QPACK streams, each once. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("the encoder stream starts", wt_http3_driver_start_qpack_stream(&driver, 1, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_ENCODER, (uint64_t)wire[0]);
  WT_EXPECT_STATUS("and not twice", WT_ERR_STATE,
                   wt_http3_driver_start_qpack_stream(&driver, 1, &w));
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("the decoder stream starts", wt_http3_driver_start_qpack_stream(&driver, 0, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_DECODER, (uint64_t)wire[0]);

  /* A payload that does not fit the caller's scratch is this endpoint's bound, and the
   * prefix is already out by then: the caller must know it. */
  {
    wt_http3_settings_t big;
    wt_http3_endpoint_t other;
    wt_http3_driver_t other_driver;
    wt_http3_endpoint_init(&other, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&other_driver, &other);
    wt_http3_settings_init(&big);
    for (i = 0U; i < 8U; i++) {
      /* LEGAL unknown identifiers, NOT the reserved family (0x21 + k*0x1f): the setter refuses those now, which is
       * the rule WT-137 restored, and a fixture that used them made this payload too small to overflow. */
      (void)wt_http3_settings_set(&big, 0x23U + (uint64_t)i * 2U, 1U);
    }
    w = wt_writer_init(wire, sizeof(wire));
    WT_EXPECT_STATUS("a settings payload that does not fit is limited", WT_ERR_LIMIT,
                     wt_http3_driver_start_control(&other_driver, &big, scratch, 2U, &w));
    WT_EXPECT_U64("after the prefix went out", 1U, (uint64_t)wt_writer_offset(&w));
  }
  (void)read_scratch;
}

/* A transport that records what it was asked to do, so the outbound half can be checked
 * without a handshake: what this layer produces IS the thing under test, and a recording sink
 * is a more exact reader than a real connection. */
typedef struct fake_transport {
  unsigned streams_opened;
  uint64_t last_stream_id;
  unsigned sends;
  size_t first_send_bytes;
  uint8_t first_bytes[512];
  size_t last_send_bytes;
  int last_fin;
  uint8_t last_bytes[512];
  unsigned datagrams;
  size_t datagram_bytes;
  int refuse_open;
} fake_transport_t;

static wt_status_t fake_open(void *context, int bidirectional, uint64_t *out_stream_id,
                             uint64_t now) {
  fake_transport_t *fake = context;
  (void)now;
  if (fake->refuse_open != 0) return WT_ERR_AGAIN;
  /* The endpoint's OWN streams (control, QPACK encoder, QPACK decoder) are unidirectional, and this test
   * only ever reaches this fake through `wt_http3_driver_start_own_streams`. The assertion used to read
   * `bidirectional ? 0 : 0`, which is 0 for every value and therefore could never fail. */
  WT_EXPECT_INT("streams this endpoint opens are unidirectional", 0, bidirectional);
  fake->streams_opened++;
  *out_stream_id = 4U * (uint64_t)fake->streams_opened;
  fake->last_stream_id = *out_stream_id;
  return WT_OK;
}

static wt_status_t fake_send(void *context, uint64_t stream_id, const uint8_t *data, size_t length,
                             int fin, uint64_t now) {
  fake_transport_t *fake = context;
  (void)now;
  if (fake->sends == 0U) {
    fake->first_send_bytes = length;
    if (length <= sizeof(fake->first_bytes)) memcpy(fake->first_bytes, data, length);
  }
  fake->sends++;
  fake->last_stream_id = stream_id;
  fake->last_fin = fin;
  fake->last_send_bytes = length;
  if (length <= sizeof(fake->last_bytes)) memcpy(fake->last_bytes, data, length);
  return WT_OK;
}

static wt_status_t fake_datagram(void *context, const uint8_t *data, size_t length) {
  fake_transport_t *fake = context;
  (void)data;
  fake->datagrams++;
  fake->datagram_bytes += length;
  return WT_OK;
}

void test_the_outbound_half_sends_what_it_should(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_transport_t transport;
  wt_http3_settings_t settings;
  wt_http3_message_t request;
  fake_transport_t fake;
  wt_cursor_t cursor;
  wt_http3_frame_t frame;
  wt_http3_settings_t read_back;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  memset(&fake, 0, sizeof(fake));
  transport.open_stream = fake_open;
  transport.send_stream = fake_send;
  transport.send_datagram = fake_datagram;
  transport.context = &fake;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a setting is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));

  /* Three streams, in the order HTTP/3 requires them: the control stream first, because it
   * carries the SETTINGS the peer needs before anything else can be interpreted. */
  WT_EXPECT_OK("an endpoint starts its own streams",
               wt_http3_driver_start_own_streams(&driver, &transport, &settings, 0U));
  WT_EXPECT_U64("three streams are opened", 3U, (uint64_t)fake.streams_opened);
  WT_EXPECT_U64("and three things sent", 3U, (uint64_t)fake.sends);

  /* What went out on the control stream is the prefix and then a SETTINGS frame, which is what
   * the reader on the other side expects. */
  WT_EXPECT_U64("the control stream's first byte is its type", WT_HTTP3_STREAM_CONTROL,
                (uint64_t)fake.first_bytes[0]);
  cursor = wt_cursor_init(fake.first_bytes + 1U, fake.first_send_bytes - 1U);
  WT_EXPECT_OK("and the rest is a frame", wt_http3_frame_decode(&cursor, &frame, &error));
  WT_EXPECT_U64("of type SETTINGS", WT_HTTP3_FRAME_SETTINGS, frame.type);
  (void)read_back;

  /* Starting them twice is the endpoint's own rule, and it is refused. */
  WT_EXPECT_STATUS("a second start is refused", WT_ERR_STATE,
                   wt_http3_driver_start_own_streams(&driver, &transport, &settings, 0U));
  WT_EXPECT_U64("without opening more", 3U, (uint64_t)fake.streams_opened);

  /* A message: the client's extended CONNECT, which is the request whose stream is the
   * session. */
  request.type = WT_HTTP3_HEADER_REQUEST;
  request.method = (const uint8_t *)"CONNECT";
  request.method_length = 7U;
  request.scheme = (const uint8_t *)"https";
  request.scheme_length = 5U;
  request.authority = (const uint8_t *)"localhost";
  request.authority_length = 9U;
  request.path = (const uint8_t *)"/chat";
  request.path_length = 5U;
  request.protocol = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN;
  request.protocol_length = strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN);
  request.status = 0U;
  request.has_status = 0;

  fake.sends = 0U;
  WT_EXPECT_OK("a request is sent",
               wt_http3_driver_send_message(&driver, &transport, 0U, &request, 0U, 0, 0U));
  WT_EXPECT_U64("as one send", 1U, (uint64_t)fake.sends);
  WT_EXPECT_U64("on the stream it was given", 0U, fake.last_stream_id);
  WT_EXPECT_INT("not ending the stream", 0, fake.last_fin);
  cursor = wt_cursor_init(fake.last_bytes, fake.last_send_bytes);
  WT_EXPECT_OK("carrying a frame", wt_http3_frame_decode(&cursor, &frame, &error));
  WT_EXPECT_U64("of type HEADERS", WT_HTTP3_FRAME_HEADERS, frame.type);

  /* A datagram, which this layer does not look inside. */
  WT_EXPECT_OK("a datagram is sent",
               wt_http3_driver_send_datagram(&driver, &transport, (const uint8_t *)"xy", 2U));
  WT_EXPECT_U64("as one datagram", 1U, (uint64_t)fake.datagrams);
  WT_EXPECT_U64("with its two bytes", 2U, (uint64_t)fake.datagram_bytes);

  /* A transport that cannot open a stream right now says so, and the driver does not pretend
   * otherwise: the refusal is the caller's, unchanged, because WT_ERR_AGAIN is congestion and
   * not an HTTP/3 condition. */
  {
    wt_http3_endpoint_t other;
    wt_http3_driver_t other_driver;
    wt_http3_endpoint_init(&other, WT_HTTP3_ROLE_CLIENT);
    wt_http3_driver_init(&other_driver, &other);
    fake.refuse_open = 1;
    WT_EXPECT_STATUS("a refused open is passed through", WT_ERR_AGAIN,
                     wt_http3_driver_start_own_streams(&other_driver, &transport, &settings, 0U));
    WT_EXPECT_U64("with nothing sent", 3U, (uint64_t)fake.streams_opened);
  }
}

/* The adapter to a real connection, checked by FORWARDING rather than by a session: a fresh
 * connection has no keys and no room, so it refuses, and the point of the test is that the
 * adapter returns exactly what the connection returns rather than inventing a status of its
 * own. That is what a thin layer has to get right, and it is the only part of it this test can
 * check without standing up a handshake. */
void test_the_quic_transport_forwards(void) {
  static const uint8_t k_dcid[8] = {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U};
  wt_quic_connection_config_t config;
  wt_quic_connection_t connection;
  wt_http3_driver_transport_t transport;
  uint64_t stream_id = 0U;
  uint64_t now = 1000U;
  wt_status_t direct;

  memset(&config, 0, sizeof(config));
  memset(&connection, 0, sizeof(connection));
  config.role = WT_QUIC_ROLE_CLIENT;
  config.version = WT_QUIC_VERSION_1;
  config.local_connection_id = k_dcid;
  config.local_connection_id_length = sizeof(k_dcid);
  config.peer_connection_id = k_dcid;
  config.peer_connection_id_length = sizeof(k_dcid);
  config.aead = WT_AEAD_AES_128_GCM;
  config.max_ack_delay = 25000U;
  config.local_max_ack_delay = 25000U;
  config.idle_timeout = 30000000U;
  config.max_datagram_size = 1200U;

  WT_EXPECT_OK("a connection is initialised", wt_quic_connection_init(&connection, &config));
  wt_http3_driver_quic_transport(&connection, &transport);
  WT_EXPECT_TRUE("the transport has an opener", transport.open_stream != NULL);
  WT_EXPECT_TRUE("a sender", transport.send_stream != NULL);
  WT_EXPECT_TRUE("and a datagram sender", transport.send_datagram != NULL);
  WT_EXPECT_TRUE("bound to the connection", transport.context == &connection);

  /* The opener's answer IS the connection's answer, whatever it is: a fresh connection has no
   * peer limits yet, so this is a refusal rather than a success, and either way the two must
   * agree. */
  direct = wt_quic_connection_open_stream(&connection, 0, &stream_id);
  WT_EXPECT_STATUS("the opener forwards the connection's answer", direct,
                   transport.open_stream(transport.context, 0, &stream_id, now));

  /* A stream the connection does not know is the caller's accounting: this layer says so
   * itself rather than letting a NULL reach the connection. */
  WT_EXPECT_STATUS("sending on an unknown stream is a state error", WT_ERR_STATE,
                   transport.send_stream(transport.context, 8U, (const uint8_t *)"x", 1U, 0, now));

  /* A datagram is forwarded, and its refusal is the connection's too. */
  direct = wt_quic_connection_send_datagram(&connection, (const uint8_t *)"x", 1U, 0U);
  WT_EXPECT_STATUS("a datagram forwards the connection's answer", direct,
                   transport.send_datagram(transport.context, (const uint8_t *)"x", 1U));
  wt_quic_connection_clear(&connection);
}

