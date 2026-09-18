/* The logging surface.
 *
 * The property that matters is the threshold: a message below a logger's level
 * must not reach the callback at all, because a library that formats a debug
 * string in production and then drops it has already paid for it. The captured
 * messages are also checked to be the caller's own strings, since the surface
 * deliberately has no formatting for peer data.
 */

#include "wt_test.h"

#include "webtransport/log.h"

typedef struct wt_capture {
  int calls;
  wt_log_level_t last_level;
  const char *last_message;
  char seen[64];
} wt_capture_t;

static void wt_capture_log(void *context, wt_log_level_t level, const char *message) {
  wt_capture_t *c = (wt_capture_t *)context;
  c->calls++;
  c->last_level = level;
  c->last_message = message;
  c->seen[0] = '\0';
  if (message != NULL) {
    size_t n = strlen(message);
    if (n >= sizeof(c->seen)) n = sizeof(c->seen) - 1U;
    memcpy(c->seen, message, n);
    c->seen[n] = '\0';
  }
}

int main(void) {
  wt_capture_t capture;
  wt_logger_t logger;

  memset(&capture, 0, sizeof(capture));

  /* No logger: nothing happens, and nothing crashes. */
  logger = wt_logger_none();
  WT_EXPECT_TRUE("a none logger has no callback", logger.fn == NULL);
  WT_EXPECT_INT("and enables nothing at error", 0, wt_log_enabled(&logger, WT_LOG_ERROR));
  wt_log_emit(&logger, WT_LOG_ERROR, "dropped");
  wt_log_emit(NULL, WT_LOG_ERROR, "dropped");
  wt_log_emit(&logger, WT_LOG_ERROR, NULL);
  WT_EXPECT_INT("a none logger emitted nothing", 0, capture.calls);

  /* A logger at ERROR admits only ERROR. */
  logger = wt_logger_to(wt_capture_log, &capture, WT_LOG_ERROR);
  WT_EXPECT_INT("error is enabled", 1, wt_log_enabled(&logger, WT_LOG_ERROR));
  WT_EXPECT_INT("warn is not", 0, wt_log_enabled(&logger, WT_LOG_WARN));
  WT_EXPECT_INT("info is not", 0, wt_log_enabled(&logger, WT_LOG_INFO));
  WT_EXPECT_INT("debug is not", 0, wt_log_enabled(&logger, WT_LOG_DEBUG));
  wt_log_emit(&logger, WT_LOG_ERROR, "an error");
  WT_EXPECT_INT("one call arrived", 1, capture.calls);
  WT_EXPECT_STR("with the message", "an error", capture.seen);
  WT_EXPECT_INT("and the level", (long)WT_LOG_ERROR, (long)capture.last_level);
  wt_log_emit(&logger, WT_LOG_DEBUG, "dropped");
  WT_EXPECT_INT("a debug message was dropped before the callback", 1, capture.calls);

  /* A logger at DEBUG admits everything, to the bottom of the range. */
  logger = wt_logger_to(wt_capture_log, &capture, WT_LOG_DEBUG);
  WT_EXPECT_INT("debug is enabled", 1, wt_log_enabled(&logger, WT_LOG_DEBUG));
  WT_EXPECT_INT("error still is", 1, wt_log_enabled(&logger, WT_LOG_ERROR));
  wt_log_emit(&logger, WT_LOG_ERROR, "e");
  wt_log_emit(&logger, WT_LOG_WARN, "w");
  wt_log_emit(&logger, WT_LOG_INFO, "i");
  wt_log_emit(&logger, WT_LOG_DEBUG, "d");
  WT_EXPECT_INT("four more calls", 5, capture.calls);
  WT_EXPECT_STR("the last was debug", "d", capture.seen);
  WT_EXPECT_INT("at the debug level", (long)WT_LOG_DEBUG, (long)capture.last_level);

  /* Emitting nothing is legal and does not reach the callback. */
  wt_log_emit(&logger, WT_LOG_ERROR, NULL);
  WT_EXPECT_INT("a NULL message is not emitted", 5, capture.calls);

  /* Level names are stable, and an out-of-range level has a name rather than a
   * crash: a log line assembled from a corrupted level still prints. */
  WT_EXPECT_STR("error is named", "error", wt_log_level_name(WT_LOG_ERROR));
  WT_EXPECT_STR("warn is named", "warn", wt_log_level_name(WT_LOG_WARN));
  WT_EXPECT_STR("info is named", "info", wt_log_level_name(WT_LOG_INFO));
  WT_EXPECT_STR("debug is named", "debug", wt_log_level_name(WT_LOG_DEBUG));
  WT_EXPECT_STR("an unknown level is named", "unknown", wt_log_level_name((wt_log_level_t)99));
  WT_EXPECT_STR("a negative level is named", "unknown", wt_log_level_name((wt_log_level_t)-1));

  /* wt_log_enabled on NULL is false rather than a crash. */
  WT_EXPECT_INT("a NULL logger enables nothing", 0, wt_log_enabled(NULL, WT_LOG_ERROR));

  WT_TEST_MAIN_END("wt_log");
}
