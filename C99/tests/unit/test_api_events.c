/* The event-loop seam (Phase 8).
 *
 * What is tested here is the contract a caller programs against: callbacks run inside the
 * call the caller made and never from the library's own thread (visible here because the
 * recording callbacks are appended to a log the test reads afterwards, in order); the
 * library does not re-enter itself, so the log is a faithful sequence; a value over a bound
 * this endpoint published is refused, while an event nobody asked about is accepted and
 * discarded rather than turned into a connection error; and the PEER's code travels through
 * a stream reset and a session close unchanged. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/api/events.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/writer.h"

/* A log of what was reported, in the order it was reported. */
typedef struct recorder {
  char events[16][32];
  size_t count;
  uint64_t last_code;
  size_t last_length;
  uint8_t last_payload[64];
  size_t streams_open_at_last_event;
} recorder_t;

static wt_session_t *g_session;

static void note(recorder_t *r, const char *text) {
  if (r->count < 16U) {
    strncpy(r->events[r->count], text, sizeof(r->events[0]) - 1U);
    r->events[r->count][sizeof(r->events[0]) - 1U] = '\0';
  }
  r->count++;
  r->streams_open_at_last_event = wt_session_stream_count(g_session);
}

static void on_open(void *context, uint64_t stream_id, int unidirectional) {
  recorder_t *r = context;
  (void)stream_id;
  note(r, unidirectional != 0 ? "open-uni" : "open-bidi");
}

static void on_data(void *context, uint64_t stream_id, const uint8_t *data, size_t length,
                    int end_stream) {
  recorder_t *r = context;
  (void)stream_id;
  r->last_length = length;
  if (length <= sizeof(r->last_payload)) memcpy(r->last_payload, data, length);
  note(r, end_stream != 0 ? "data-end" : "data");
}

static void on_reset(void *context, uint64_t stream_id, uint64_t error_code) {
  recorder_t *r = context;
  (void)stream_id;
  r->last_code = error_code;
  note(r, "reset");
}

static void on_datagram(void *context, const uint8_t *data, size_t length) {
  recorder_t *r = context;
  r->last_length = length;
  if (length <= sizeof(r->last_payload)) memcpy(r->last_payload, data, length);
  note(r, "datagram");
}

static void on_drain(void *context) { note((recorder_t *)context, "drain"); }
static void on_close(void *context, uint32_t error_code) {
  recorder_t *r = context;
  r->last_code = error_code;
  note(r, "close");
}

static void install(wt_session_t *session, recorder_t *r, wt_session_callbacks_t *callbacks) {
  callbacks->context = r;
  callbacks->on_stream_opened = on_open;
  callbacks->on_stream_data = on_data;
  callbacks->on_stream_reset = on_reset;
  callbacks->on_datagram = on_datagram;
  callbacks->on_drain = on_drain;
  callbacks->on_close = on_close;
  WT_EXPECT_OK("the callbacks install", wt_session_set_callbacks(session, callbacks));
}

static wt_session_t *make_session(recorder_t *r, wt_session_callbacks_t *callbacks) {
  wt_session_config_t config;
  wt_session_t *session = NULL;

  config.authority = "localhost";
  config.path = "/wt";
  config.session_id = 4U; /* the first client-bidirectional CONNECT stream */
  config.max_capsule_bytes = 128U;
  config.max_datagram_bytes = 32U;
  config.max_streams = 2U;
  WT_EXPECT_OK("a session is created", wt_session_create(&config, NULL, &session));
  WT_EXPECT_OK("and established", wt_session_established(session));
  WT_EXPECT_U64("with the CONNECT stream ID it was made for", 4U, wt_session_id(session));
  install(session, r, callbacks);
  g_session = session;
  return session;
}

static void test_streams(void) {
  recorder_t recorder;
  wt_session_callbacks_t callbacks;
  wt_session_t *session;
  uint8_t bytes[16];

  memset(&recorder, 0, sizeof(recorder));
  memset(&callbacks, 0, sizeof(callbacks));
  session = make_session(&recorder, &callbacks);

  /* A stream for ANOTHER session is refused and reported with HTTP/3's identifier error:
   * it is not delivered to the wrong session and not silently dropped. */
  WT_EXPECT_STATUS("a stream for another session is refused", WT_ERR_STATE,
                   wt_session_on_stream_opened(session, 8U, 0, 12U));
  WT_EXPECT_U64("with the identifier error as the code", (uint64_t)WT_HTTP3_ID_ERROR,
                (uint64_t)wt_session_last_error(session).code);
  WT_EXPECT_U64("and nothing reported", 0U, (uint64_t)recorder.count);
  WT_EXPECT_U64("and nothing tracked", 0U, (uint64_t)wt_session_stream_count(session));

  /* Opening, then data, then the peer's end: three reports in that order. */
  WT_EXPECT_OK("a stream opens", wt_session_on_stream_opened(session, 8U, 1, 4U));
  WT_EXPECT_U64("which is tracked", 1U, (uint64_t)wt_session_stream_count(session));
  bytes[0] = 0x41U;
  WT_EXPECT_OK("data arrives", wt_session_on_stream_data(session, 8U, bytes, 1U, 0));
  WT_EXPECT_OK("and the end", wt_session_on_stream_data(session, 8U, bytes, 0U, 1));
  WT_EXPECT_U64("leaving nothing tracked", 0U, (uint64_t)wt_session_stream_count(session));
  WT_EXPECT_U64("with three reports", 3U, (uint64_t)recorder.count);
  WT_EXPECT_STR("in wire order", "open-uni", recorder.events[0]);
  WT_EXPECT_STR("then data", "data", recorder.events[1]);
  WT_EXPECT_STR("then the end", "data-end", recorder.events[2]);
  WT_EXPECT_U64("and the stream was open during its last callback", 1U,
                (uint64_t)recorder.streams_open_at_last_event);

  /* Data on a stream that was never opened is the APPLICATION's ordering problem. */
  WT_EXPECT_STATUS("data on an unopened stream is refused", WT_ERR_STATE,
                   wt_session_on_stream_data(session, 12U, bytes, 1U, 0));
  WT_EXPECT_STATUS("as is a reset", WT_ERR_STATE, wt_session_on_stream_reset(session, 12U, 7U));

  /* A reset carries the peer's code through, and stops the tracking. */
  WT_EXPECT_OK("a second stream opens", wt_session_on_stream_opened(session, 12U, 0, 4U));
  WT_EXPECT_STATUS("opening it twice is refused", WT_ERR_STATE,
                   wt_session_on_stream_opened(session, 12U, 0, 4U));
  WT_EXPECT_OK("and a reset is applied", wt_session_on_stream_reset(session, 12U, 0x01020304U));
  WT_EXPECT_U64("with the peer's code", 0x01020304U, recorder.last_code);
  WT_EXPECT_U64("and nothing tracked", 0U, (uint64_t)wt_session_stream_count(session));

  /* The bound this endpoint published: max_streams is 2, and the table is the handle's. */
  WT_EXPECT_OK("a stream opens", wt_session_on_stream_opened(session, 16U, 1, 4U));
  WT_EXPECT_OK("and another", wt_session_on_stream_opened(session, 20U, 1, 4U));
  WT_EXPECT_STATUS("a third is refused", WT_ERR_LIMIT,
                   wt_session_on_stream_opened(session, 24U, 1, 4U));
  WT_EXPECT_U64("as excessive load rather than a malformed stream", (uint64_t)WT_HTTP3_EXCESSIVE_LOAD,
                (uint64_t)wt_session_last_error(session).code);
  WT_EXPECT_U64("with the table unchanged", 2U, (uint64_t)wt_session_stream_count(session));

  wt_session_destroy(session, NULL);
  g_session = NULL;
}

static void test_datagrams_and_capsules(void) {
  recorder_t recorder;
  wt_session_callbacks_t callbacks;
  wt_session_t *session;
  uint8_t bytes[64];
  size_t length;

  memset(&recorder, 0, sizeof(recorder));
  memset(&callbacks, 0, sizeof(callbacks));
  session = make_session(&recorder, &callbacks);

  /* A datagram is delivered with its quarter stream ID stripped, and its payload is a view
   * of the caller's buffer for the duration of the callback only. */
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a datagram writes", wt_webtransport_datagram_write(&w, 1U, (const uint8_t *)"hi", 2U));
    WT_EXPECT_OK("and is delivered",
                 wt_session_on_datagram(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_STR("as one report", "datagram", recorder.events[0]);
    WT_EXPECT_U64("with the payload's length", 2U, (uint64_t)recorder.last_length);
    WT_EXPECT_BYTES("and its bytes", (const uint8_t *)"hi", recorder.last_payload, 2U);
  }

  /* A datagram for another session is refused, not delivered to this one. */
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("another session's datagram writes",
                 wt_webtransport_datagram_write(&w, 7U, (const uint8_t *)"x", 1U));
    WT_EXPECT_STATUS("and is refused", WT_ERR_STATE,
                     wt_session_on_datagram(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_U64("with the identifier error", (uint64_t)WT_HTTP3_ID_ERROR,
                  (uint64_t)wt_session_last_error(session).code);
  }

  /* The datagram bound is this endpoint's, and a payload over it is refused as excessive
   * load rather than buffered. */
  {
    uint8_t big[48];
    wt_writer_t w;
    memset(big, 0x5a, sizeof(big));
    w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("an oversized datagram writes",
                 wt_webtransport_datagram_write(&w, 1U, big, sizeof(big)));
    WT_EXPECT_STATUS("and is refused", WT_ERR_LIMIT,
                     wt_session_on_datagram(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_U64("as excessive load", (uint64_t)WT_HTTP3_EXCESSIVE_LOAD,
                  (uint64_t)wt_session_last_error(session).code);
  }

  /* A datagram that does not hold its quarter ID at all is malformed -- a datagram IS the
   * unit, which is the one place this library refuses an incomplete message. */
  WT_EXPECT_STATUS("an empty datagram is malformed", WT_ERR_PROTOCOL,
                   wt_session_on_datagram(session, bytes, 0U));

  /* The capsules on the CONNECT stream report through the same seam. */
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a drain writes", wt_webtransport_drain_session_write(&w));
    WT_EXPECT_OK("and is reported", wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_STR("as a drain", "drain", recorder.events[recorder.count - 1U]);
  }
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a close writes",
                 wt_webtransport_close_session_write(&w, 0x0badf00dU, (const uint8_t *)"text", 4U));
    WT_EXPECT_OK("and is reported", wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_STR("as a close", "close", recorder.events[recorder.count - 1U]);
    WT_EXPECT_U64("with the peer's code", 0x0badf00dU, recorder.last_code);
  }

  /* Clearing the callbacks stops delivery without refusing anything: an event nobody asked
   * about is accepted and discarded, because blaming the peer for our configuration would
   * be wrong. */
  WT_EXPECT_OK("the callbacks are cleared", wt_session_set_callbacks(session, NULL));
  {
    size_t before = recorder.count;
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a datagram writes", wt_webtransport_datagram_write(&w, 1U, (const uint8_t *)"ok", 2U));
    WT_EXPECT_OK("and is accepted", wt_session_on_datagram(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_U64("with nothing reported", (uint64_t)before, (uint64_t)recorder.count);
  }
  (void)length;
  wt_session_destroy(session, NULL);
  g_session = NULL;
}

static void test_configuration_bounds(void) {
  wt_session_config_t config;
  wt_session_t *session = NULL;

  config = wt_session_config_default();
  config.authority = "localhost";
  config.path = "/wt";
  config.session_id = 4U;
  config.max_capsule_bytes = 128U;
  config.max_datagram_bytes = WT_SESSION_DATAGRAM_MAX + 1U;
  WT_EXPECT_STATUS("a datagram bound over the ceiling is refused", WT_ERR_LIMIT,
                   wt_session_create(&config, NULL, &session));
  WT_EXPECT_TRUE("with no handle", session == NULL);

  config.max_datagram_bytes = (size_t)WT_SESSION_DATAGRAM_MAX;
  config.max_streams = (size_t)WT_SESSION_STREAM_MAX + 1U;
  WT_EXPECT_STATUS("and a stream table bigger than the build is refused", WT_ERR_LIMIT,
                   wt_session_create(&config, NULL, &session));

  /* Zero means the handle's own maximum in both cases. */
  config.max_streams = 0U;
  config.max_datagram_bytes = 0U;
  WT_EXPECT_OK("zero means the handle's maximum", wt_session_create(&config, NULL, &session));
  wt_session_destroy(session, NULL);
}

int main(void) {
  test_streams();
  test_datagrams_and_capsules();
  test_configuration_bounds();
  WT_TEST_MAIN_END("wt_api_events");
}
