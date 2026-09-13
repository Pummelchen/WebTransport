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
}

int main(void) {
  test_the_layers_are_reachable();
  WT_EXPECT_STR("the version is reported", wt_version_string(), wt_version_string());
  WT_EXPECT_STR("and the draft", "draft-ietf-webtrans-http3-16", wt_protocol_draft());
  WT_TEST_MAIN_END("wt_public_api");
}
