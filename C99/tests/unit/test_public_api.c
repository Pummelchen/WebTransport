/* The umbrella header (include/webtransport/webtransport.h).
 *
 * A consumer includes one header, so this test includes ONE header and then uses a piece
 * of every layer. It is a compile-time check more than a runtime one: a module missing
 * from the umbrella, a header that does not include what it uses, or a layer whose
 * declarations moved would fail to build here rather than in a consumer's project. What
 * it asserts at runtime is the smallest true thing about each layer, so that the test
 * cannot pass while a layer is stubbed out. */

#include "wt_test.h"

#include "webtransport/webtransport.h"

static void test_the_layers_are_reachable(void) {
  uint8_t bytes[64];
  wt_writer_t w;
  wt_cursor_t c;
  wt_http3_frame_t decoded;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint64_t value = 0U;

  /* Core: a writer and a cursor over the same bytes. */
  w = wt_writer_init(bytes, sizeof(bytes));
  wt_writer_u32(&w, 0x01020304U);
  WT_EXPECT_OK("the core writes", wt_writer_ok(&w) ? WT_OK : WT_ERR_LIMIT);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_U64("and reads", 0x01020304U, (uint64_t)wt_cursor_u32(&c));

  /* QUIC: a varint. */
  w = wt_writer_init(bytes, sizeof(bytes));
  (void)wt_quic_writer_varint(&w, 0x1234U);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("a QUIC varint round trips", wt_quic_varint_decode(&c, &value));
  WT_EXPECT_U64("to its value", 0x1234U, value);

  /* HTTP/3: a frame. */
  w = wt_writer_init(bytes, sizeof(bytes));
  {
    wt_http3_frame_t frame = wt_http3_frame_make(WT_HTTP3_FRAME_DATA);
    frame.payload = (const uint8_t *)"x";
    frame.length = 1U;
    WT_EXPECT_OK("an HTTP/3 frame writes", wt_http3_frame_encode(&w, &frame));
  }
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_http3_frame_decode(&c, &decoded, &h3_error));
  WT_EXPECT_U64("as data", WT_HTTP3_FRAME_DATA, decoded.type);

  /* QPACK: a static entry. */
  {
    wt_qpack_static_entry_t entry;
    WT_EXPECT_OK("the QPACK static table is reachable", wt_qpack_static_entry(0U, &entry));
    WT_EXPECT_BYTES("with :authority first", (const uint8_t *)":authority",
                    (const uint8_t *)entry.name, entry.name_length);
  }

  /* The draft-16 session layer: a drain capsule, which exercises the capsule codec. */
  {
    wt_webtransport_capsule_t capsule;
    w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a session drain writes", wt_webtransport_drain_session_write(&w));
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_OK("and decodes as a capsule",
                 wt_webtransport_capsule_decode(&c, 64U, &capsule, &h3_error));
    WT_EXPECT_U64("named as a drain", WT_CAPSULE_DRAIN_SESSION, capsule.type);
  }
  /* The consumer API: a session created through the umbrella alone, with its flow
   * control configured, so a declaration that moved out of the umbrella fails HERE. */
  {
    wt_session_config_t config = wt_session_config_default();
    wt_session_t *session = NULL;
    wt_session_callbacks_t callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    wt_endpoint_config_t endpoint = wt_endpoint_config_default();
    endpoint.role = WT_ENDPOINT_ROLE_CLIENT;
    endpoint.host = "localhost";
    endpoint.port = 443U;
    endpoint.trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
    WT_EXPECT_OK("an endpoint checks out", wt_endpoint_config_check(&endpoint));
    WT_EXPECT_OK("and builds a session configuration",
                 wt_endpoint_session_config(&endpoint, 4U, &config));
    config.max_capsule_bytes = 4096U;
    WT_EXPECT_OK("a session is created from the umbrella alone",
                 wt_session_create(&config, NULL, &session));
    WT_EXPECT_OK("its callbacks install", wt_session_set_callbacks(session, &callbacks));
    WT_EXPECT_OK("and its flow control configures",
                 wt_session_flow_configure(session, 1, 100U, 1U, 1U));
    WT_EXPECT_U64("with an allowance", 100U, wt_session_flow_data_allowance(session));
    WT_EXPECT_INT("and a state to read", (int)WT_SESSION_ESTABLISHING,
                  (int)wt_session_state(session));
    wt_session_destroy(session, NULL);
  }
}

int main(void) {
  test_the_layers_are_reachable();
  WT_EXPECT_STR("the version is reported", "0.1.0", wt_version_string());
  WT_EXPECT_STR("and the draft", "draft-ietf-webtrans-http3-16", wt_protocol_draft());
  WT_TEST_MAIN_END("wt_public_api");
}
