/* The public session handle (Phase 8).
 *
 * The API's promises are about SHAPE rather than protocol, so these tests are about the
 * shape: a handle created and destroyed through the CALLER's allocator (counted, so a leak
 * or a double free fails here), a state a consumer reads without a header of ours, an error
 * surface that carries a stable status name and the PEER's code rather than any peer text,
 * and the two bounds the API owns -- a capsule larger than the session accepts, and an
 * authority too long for the handle's copy. */

#include "wt_test.h"

#include <stdlib.h>
#include <string.h>

#include "webtransport/api/flow.h"
#include "webtransport/api/session.h"
#include "webtransport/cursor.h"
#include "webtransport/http3/frame.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/writer.h"

/* An allocator that counts, so the test can say the object came back. */
typedef struct counting_allocator {
  size_t allocations;
  size_t frees;
  int live;
} counting_allocator_t;

static void *counting_alloc(void *context, size_t size) {
  counting_allocator_t *counter = context;
  void *memory = malloc(size);
  if (memory != NULL) {
    counter->allocations++;
    counter->live++;
  }
  return memory;
}

static void *counting_realloc(void *context, void *ptr, size_t old_size, size_t new_size) {
  (void)context;
  (void)old_size;
  return realloc(ptr, new_size);
}

static void counting_free(void *context, void *ptr, size_t size) {
  counting_allocator_t *counter = context;
  (void)size;
  if (ptr != NULL) {
    counter->frees++;
    counter->live--;
  }
  free(ptr);
}

static void test_create_and_destroy(void) {
  counting_allocator_t counter;
  wt_allocator_t allocator;
  wt_session_config_t config;
  wt_session_t *session = NULL;
  wt_status_t status;
  char too_long[200];

  memset(&counter, 0, sizeof(counter));
  allocator.context = &counter;
  allocator.alloc = counting_alloc;
  allocator.realloc = counting_realloc;
  allocator.free = counting_free;

  config = wt_session_config_default();
  config.authority = "localhost";
  config.path = "/wt";
  config.max_capsule_bytes = 1024U;

  WT_EXPECT_OK("a session is created", wt_session_create(&config, &allocator, &session));
  WT_EXPECT_TRUE("with a handle", session != NULL);
  WT_EXPECT_U64("through the caller's allocator", 1U, (uint64_t)counter.allocations);
  WT_EXPECT_INT("live", 1, counter.live);
  WT_EXPECT_INT("starting in the establishing state", (int)WT_SESSION_ESTABLISHING,
                (int)wt_session_state(session));

  WT_EXPECT_OK("the session is established", wt_session_established(session));
  WT_EXPECT_INT("which its state shows", (int)WT_SESSION_ESTABLISHED,
                (int)wt_session_state(session));
  status = wt_session_established(session);
  WT_EXPECT_STATUS("and establishing twice is refused", WT_ERR_STATE, status);
  WT_EXPECT_U64("with the error recorded", (uint64_t)WT_ERR_STATE,
                (uint64_t)wt_session_last_error(session).status);

  WT_EXPECT_STR("the status has a stable name", "state", wt_session_status_name(WT_ERR_STATE));

  wt_session_destroy(session, &allocator);
  WT_EXPECT_U64("and the object came back", 1U, (uint64_t)counter.frees);
  WT_EXPECT_INT("with nothing left live", 0, counter.live);

  /* A configuration this API cannot copy is refused rather than truncated: a truncated
   * authority would name a different session. */
  memset(too_long, 'a', sizeof(too_long) - 1U);
  too_long[sizeof(too_long) - 1U] = '\0';
  config.authority = too_long;
  session = NULL;
  WT_EXPECT_STATUS("an authority too long for the handle is refused", WT_ERR_LIMIT,
                   wt_session_create(&config, &allocator, &session));
  WT_EXPECT_TRUE("with no handle", session == NULL);
  WT_EXPECT_U64("and nothing allocated", 1U, (uint64_t)counter.allocations);

  /* NULL arguments are the API's own guard, not the protocol's. */
  config.authority = "localhost";
  WT_EXPECT_STATUS("a NULL configuration is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_session_create(NULL, &allocator, &session));
  WT_EXPECT_STATUS("as is a NULL out-parameter", WT_ERR_INVALID_ARGUMENT,
                   wt_session_create(&config, &allocator, NULL));
  wt_session_destroy(NULL, NULL);
}

static void test_capsules_and_the_sanitized_error(void) {
  wt_session_config_t config;
  wt_session_t *session = NULL;
  uint8_t bytes[128];
  size_t length = 0U;
  wt_session_error_t error;

  config = wt_session_config_default();
  config.authority = "localhost";
  config.path = "/wt";
  config.max_capsule_bytes = 64U;

  WT_EXPECT_OK("a session is created", wt_session_create(&config, NULL, &session));
  WT_EXPECT_OK("and established", wt_session_established(session));

  /* A drain from the peer moves the state and records no code. */
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a drain writes", wt_webtransport_drain_session_write(&w));
    WT_EXPECT_OK("and is applied", wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_INT("moving the session to draining", (int)WT_SESSION_DRAINING,
                  (int)wt_session_state(session));
    error = wt_session_last_error(session);
    WT_EXPECT_U64("with no code", 0U, error.code);
  }

  /* A close from the peer carries ITS code to the caller: that is the sanitized surface's
   * promise -- a number, never a peer's text, even though the peer sent text. */
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    WT_EXPECT_OK("a close writes", wt_webtransport_close_session_write(
                                       &w, 0x01020304U, (const uint8_t *)"peer text", 9U));
    WT_EXPECT_OK("and is applied", wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
    WT_EXPECT_INT("closing the session", (int)WT_SESSION_CLOSED, (int)wt_session_state(session));
    error = wt_session_last_error(session);
    WT_EXPECT_U64("with the peer's code", 0x01020304U, error.code);
    WT_EXPECT_U64("and an ok status, because the close was understood", (uint64_t)WT_OK,
                  (uint64_t)error.status);
  }

  /* A transition on a closed session is refused: a capsule after the end is a message the
   * peer has no state for. */
  WT_EXPECT_STATUS("a drain on a closed session is refused", WT_ERR_STATE,
                   wt_session_write_drain(session, bytes, sizeof(bytes), &length));
  WT_EXPECT_U64("and nothing was written", 0U, (uint64_t)length);
  WT_EXPECT_STATUS("as is a close", WT_ERR_STATE,
                   wt_session_write_close(session, 0U, "bye", bytes, sizeof(bytes), &length));

  wt_session_destroy(session, NULL);
}

/* Sections 4.7 and 6: this entry point must apply the same two rules the machine walker applies to the same
 * bytes. Section 4.7 Figure 5 fixes a WT_DRAIN_SESSION's Length at 0, so a value is a capsule this layer cannot
 * read rather than one it may ignore; and section 6 ends the session at the close, so "if any additional stream
 * data is received on the CONNECT stream after receiving a WT_CLOSE_SESSION capsule, the stream MUST be reset
 * with code H3_MESSAGE_ERROR". The two entry points disagreeing was how a peer could raise its own data limit
 * after the session had ended. */
static void test_the_entry_point_refuses_what_the_walker_refuses(void) {
  wt_session_config_t config;
  wt_session_t *session = NULL;
  uint8_t bytes[64];
  wt_writer_t w;
  wt_session_error_t error;

  config = wt_session_config_default();
  config.authority = "localhost";
  config.path = "/wt";
  config.max_capsule_bytes = 128U;

  WT_EXPECT_OK("a session is created", wt_session_create(&config, NULL, &session));
  WT_EXPECT_OK("and established", wt_session_established(session));
  WT_EXPECT_OK("with a data limit", wt_session_flow_configure(session, 1, 100U, 0U, 0U));

  /* The drain's encoding is the type 0x78ae and a one-byte length 1 followed by a value. */
  {
    static const uint8_t k_drain_with_a_value[] = {0x80U, 0x00U, 0x78U, 0xaeU, 0x01U, 0x2aU};
    WT_EXPECT_STATUS(
        "a drain carrying a value is refused", WT_ERR_PROTOCOL,
        wt_session_on_capsule(session, k_drain_with_a_value, sizeof(k_drain_with_a_value)));
    error = wt_session_last_error(session);
    WT_EXPECT_U64("as a message error", (uint64_t)WT_HTTP3_MESSAGE_ERROR, error.code);
    WT_EXPECT_INT("leaving the session where it was", (int)WT_SESSION_ESTABLISHED,
                  (int)wt_session_state(session));
  }

  /* Close it, then grant more data: a capsule after the close is a message the peer has no state for. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a close writes", wt_webtransport_close_session_write(&w, 0U, NULL, 0U));
  WT_EXPECT_OK("and is applied", wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a bigger grant writes", wt_webtransport_max_data_write(&w, 200U));
  WT_EXPECT_STATUS("a capsule after the close is refused", WT_ERR_PROTOCOL,
                   wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
  error = wt_session_last_error(session);
  WT_EXPECT_U64("as a message error", (uint64_t)WT_HTTP3_MESSAGE_ERROR, error.code);
  WT_EXPECT_U64("and the peer's data limit is unchanged", 100U,
                wt_session_flow_data_allowance(session));

  wt_session_destroy(session, NULL);
}

static void test_the_capsule_bound(void) {
  wt_session_config_t config;
  wt_session_t *session = NULL;
  /* MAX_DATA's value is one varint, so a value whose length is over the session's bound is
   * spelled with a long varint prefix followed by filler. The bound is the SESSION's, and
   * a peer that exceeds it must be told the bound was reached rather than have the value
   * buffered. */
  static uint8_t oversized[80];
  wt_session_error_t error;

  config = wt_session_config_default();
  config.authority = "localhost";
  config.path = "/wt";
  config.max_capsule_bytes = 32U;
  WT_EXPECT_OK("a session is created", wt_session_create(&config, NULL, &session));

  { /* MAX_DATA (0x01) whose value is a single varint: inside the bound. */
    static uint8_t at_bound[3U];
    at_bound[0] = 0x01U; /* MAX_DATA */
    at_bound[1] = 0x01U; /* a one-byte value, well inside the 32-byte bound */
    at_bound[2] = 0x2aU;
    WT_EXPECT_OK("a capsule inside the bound is applied",
                 wt_session_on_capsule(session, at_bound, sizeof(at_bound)));
  }

  { /* MAX_DATA with a 64-byte value against a 32-byte bound. */
    size_t i;
    oversized[0] = 0x01U;
    oversized[1] = 0x40U;
    oversized[2] = 0x3fU;
    for (i = 3U; i < sizeof(oversized); i++)
      oversized[i] = 0x00U;
    WT_EXPECT_STATUS("one over the bound is refused", WT_ERR_LIMIT,
                     wt_session_on_capsule(session, oversized, sizeof(oversized)));
    error = wt_session_last_error(session);
    WT_EXPECT_U64("with the excessive-load code, not the peer's", 0x0107U, error.code);
  }

  /* An incomplete capsule is not a refusal: more may arrive. */
  WT_EXPECT_STATUS("an incomplete capsule is reported as truncated", WT_ERR_TRUNCATED,
                   wt_session_on_capsule(session, oversized, 1U));
  WT_EXPECT_STATUS("and nothing at all is an argument error", WT_ERR_INVALID_ARGUMENT,
                   wt_session_on_capsule(session, NULL, 4U));

  wt_session_destroy(session, NULL);
}

/* The bytes `wt_session_write_drain` and `wt_session_write_close` return are what goes on the CONNECT stream, and
 * what goes there is a DATA frame (RFC 9114 section 4.4) whose payload is the capsule (RFC 9297 section 3.2). A
 * capsule written raw is the header of an UNKNOWN frame type, which a peer ignores in silence -- so a caller that
 * cannot tell the difference has no way to notice that its drain never arrived (WT-249). */
static void test_the_written_capsules_are_framed_for_the_connect_stream(void) {
  wt_session_config_t config;
  wt_session_t *session = NULL;
  uint8_t wire[128];
  size_t length = 0U;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;

  config = wt_session_config_default();
  config.authority = "localhost";
  config.path = "/wt";
  WT_EXPECT_OK("a session is created", wt_session_create(&config, NULL, &session));
  WT_EXPECT_OK("and established", wt_session_established(session));

  WT_EXPECT_OK("a drain is written", wt_session_write_drain(session, wire, sizeof(wire), &length));
  {
    wt_cursor_t cursor = wt_cursor_init(wire, length);
    wt_http3_frame_t frame;
    wt_webtransport_capsule_t capsule;
    wt_cursor_t capsule_cursor;

    WT_EXPECT_OK("the write is one HTTP/3 frame",
                 wt_http3_frame_decode(&cursor, &frame, &h3_error));
    WT_EXPECT_U64("of type DATA", WT_HTTP3_FRAME_DATA, frame.type);
    WT_EXPECT_TRUE("with the whole write accounted for", wt_cursor_at_end(&cursor) != 0);
    capsule_cursor = wt_cursor_init(frame.payload, frame.length);
    memset(&capsule, 0, sizeof(capsule));
    WT_EXPECT_OK(
        "whose payload is a capsule",
        wt_webtransport_capsule_decode(&capsule_cursor, frame.length, &capsule, &h3_error));
    WT_EXPECT_U64("of type DRAIN_SESSION", WT_CAPSULE_DRAIN_SESSION, capsule.type);
    WT_EXPECT_U64("with no value", 0U, (uint64_t)capsule.value_length);
  }

  /* A close, whose capsule is longer than the DATA header's one-byte length form: the frame header grows and the
   * payload still sits directly behind it. */
  WT_EXPECT_OK("a close is written", wt_session_write_close(session, 0x01020304U, "framed payload",
                                                            wire, sizeof(wire), &length));
  {
    wt_cursor_t cursor = wt_cursor_init(wire, length);
    wt_http3_frame_t frame;
    wt_webtransport_capsule_t capsule;
    wt_cursor_t capsule_cursor;
    uint32_t code = 0U;
    const uint8_t *reason = NULL;
    size_t reason_length = 0U;

    WT_EXPECT_OK("the close is one HTTP/3 frame",
                 wt_http3_frame_decode(&cursor, &frame, &h3_error));
    WT_EXPECT_U64("of type DATA", WT_HTTP3_FRAME_DATA, frame.type);
    capsule_cursor = wt_cursor_init(frame.payload, frame.length);
    memset(&capsule, 0, sizeof(capsule));
    WT_EXPECT_OK(
        "whose payload is the close capsule",
        wt_webtransport_capsule_decode(&capsule_cursor, frame.length, &capsule, &h3_error));
    WT_EXPECT_OK("which parses", wt_webtransport_close_session_parse(&capsule, &code, &reason,
                                                                     &reason_length, &h3_error));
    WT_EXPECT_U64("with the caller's code", 0x01020304U, (uint64_t)code);
    WT_EXPECT_U64("and the caller's reason", (uint64_t)strlen("framed payload"),
                  (uint64_t)reason_length);
    WT_EXPECT_BYTES("byte for byte", (const uint8_t *)"framed payload", reason, reason_length);
  }

  /* A buffer that cannot hold the framing is refused rather than truncated, and the session's own error says so. */
  {
    wt_session_config_t small = wt_session_config_default();
    wt_session_t *bounded = NULL;
    uint8_t tiny[4];
    size_t tiny_length = 0U;
    wt_session_error_t error;

    small.authority = "localhost";
    small.path = "/wt";
    WT_EXPECT_OK("a second session is created", wt_session_create(&small, NULL, &bounded));
    WT_EXPECT_OK("and established", wt_session_established(bounded));
    WT_EXPECT_STATUS("a buffer with no room for the frame is refused", WT_ERR_LIMIT,
                     wt_session_write_drain(bounded, tiny, sizeof(tiny), &tiny_length));
    WT_EXPECT_U64("with nothing written", 0U, (uint64_t)tiny_length);
    error = wt_session_last_error(bounded);
    WT_EXPECT_U64("and the refusal is the session's own", (uint64_t)WT_ERR_LIMIT,
                  (uint64_t)error.status);
    /* The state moved only if the bytes did: a caller whose buffer was too small has a session it can still
     * drain into a bigger one, rather than one that says it is draining and has told nobody. */
    WT_EXPECT_INT("and the state did not move with it", (int)WT_SESSION_ESTABLISHED,
                  (int)wt_session_state(bounded));
    wt_session_destroy(bounded, NULL);
  }

  wt_session_destroy(session, NULL);
}

int main(void) {
  test_create_and_destroy();
  test_capsules_and_the_sanitized_error();
  test_the_entry_point_refuses_what_the_walker_refuses();
  test_the_capsule_bound();
  test_the_written_capsules_are_framed_for_the_connect_stream();
  WT_TEST_MAIN_END("wt_api_session");
}
