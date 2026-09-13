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

#include "webtransport/api/session.h"
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
  WT_EXPECT_INT("which its state shows", (int)WT_SESSION_ESTABLISHED, (int)wt_session_state(session));
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
    WT_EXPECT_OK("a close writes",
                 wt_webtransport_close_session_write(&w, 0x01020304U, (const uint8_t *)"peer text",
                                                     9U));
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
    for (i = 3U; i < sizeof(oversized); i++) oversized[i] = 0x00U;
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

int main(void) {
  test_create_and_destroy();
  test_capsules_and_the_sanitized_error();
  test_the_capsule_bound();
  WT_TEST_MAIN_END("wt_api_session");
}
