/* Machine-readable scenario results (Phase 9).
 *
 * A conformance report is only useful if it cannot lie, so the tests are about the ways it could:
 * an unattempted scenario must not read as a pass, a full report must refuse rather than drop, a
 * name too long for the table must be refused rather than truncated (a truncated name is a
 * different scenario), and the exit status must agree with the summary rather than replace it. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/cli/report.h"

static void test_an_unattempted_scenario_is_not_a_pass(void) {
  wt_cli_report_t report;
  FILE *stream;
  char buffer[1024];
  size_t read_length;

  wt_cli_report_init(&report);
  WT_EXPECT_U64("a fresh report holds nothing", 0U, (uint64_t)wt_cli_report_count(&report));
  WT_EXPECT_INT("and would exit clean, which is why a tool must add its scenarios", 0,
                wt_cli_report_exit_status(&report));

  WT_EXPECT_OK("a pass is recorded",
               wt_cli_report_add(&report, "varint-boundaries", WT_CLI_RESULT_PASSED, "all forms"));
  WT_EXPECT_OK("a failure is recorded", wt_cli_report_add(&report, "capsule-roundtrip",
                                                          WT_CLI_RESULT_FAILED, "length wrong"));
  WT_EXPECT_OK("and an unattempted one is recorded as such",
               wt_cli_report_add(&report, "session-over-udp", WT_CLI_RESULT_UNSUPPORTED,
                                 "needs the packet-session wiring"));
  WT_EXPECT_U64("three scenarios", 3U, (uint64_t)wt_cli_report_count(&report));
  WT_EXPECT_U64("one passed", 1U, (uint64_t)wt_cli_report_count_of(&report, WT_CLI_RESULT_PASSED));
  WT_EXPECT_U64("one failed", 1U, (uint64_t)wt_cli_report_count_of(&report, WT_CLI_RESULT_FAILED));
  WT_EXPECT_U64("one unsupported", 1U,
                (uint64_t)wt_cli_report_count_of(&report, WT_CLI_RESULT_UNSUPPORTED));
  WT_EXPECT_INT("and the exit status is the failure, not the pass", 1,
                wt_cli_report_exit_status(&report));

  WT_EXPECT_STR("the names are stable", "passed", wt_cli_result_name(WT_CLI_RESULT_PASSED));
  WT_EXPECT_STR("for a failure", "failed", wt_cli_result_name(WT_CLI_RESULT_FAILED));
  WT_EXPECT_STR("and for an unattempted scenario", "unsupported",
                wt_cli_result_name(WT_CLI_RESULT_UNSUPPORTED));

  /* The JSON is the product, so it is asserted as text: a script matches these field names. */
  stream = tmpfile();
  WT_EXPECT_TRUE("a stream opens", stream != NULL);
  if (stream != NULL) {
    wt_cli_report_write_json(&report, stream);
    rewind(stream);
    read_length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
    buffer[read_length] = '\0';
    fclose(stream);
    WT_EXPECT_TRUE("the object names the scenarios", strstr(buffer, "\"scenarios\":[") != NULL);
    WT_EXPECT_TRUE("with a name", strstr(buffer, "\"name\":\"varint-boundaries\"") != NULL);
    WT_EXPECT_TRUE("a result", strstr(buffer, "\"result\":\"passed\"") != NULL);
    WT_EXPECT_TRUE("a detail", strstr(buffer, "\"detail\":\"all forms\"") != NULL);
    WT_EXPECT_TRUE("and a summary",
                   strstr(buffer, "\"summary\":{\"total\":3,\"passed\":1,"
                                  "\"failed\":1,\"unsupported\":1,\"rejected\":0}") != NULL);
  }

  /* Without a failure, an unattempted scenario is still not success: the status says so. */
  wt_cli_report_init(&report);
  WT_EXPECT_OK("only a pass is recorded",
               wt_cli_report_add(&report, "a", WT_CLI_RESULT_PASSED, ""));
  WT_EXPECT_INT("which exits clean", 0, wt_cli_report_exit_status(&report));
  WT_EXPECT_OK("and then an unattempted scenario",
               wt_cli_report_add(&report, "b", WT_CLI_RESULT_UNSUPPORTED, "not wired yet"));
  WT_EXPECT_INT("which exits 3 rather than 0", 3, wt_cli_report_exit_status(&report));
}

static void test_the_report_refuses_rather_than_drops(void) {
  wt_cli_report_t report;
  char long_name[WT_CLI_SCENARIO_NAME_MAX + 2U];
  char long_detail[WT_CLI_SCENARIO_DETAIL_MAX + 2U];
  size_t i;

  wt_cli_report_init(&report);
  memset(long_name, 'a', sizeof(long_name) - 1U);
  long_name[sizeof(long_name) - 1U] = '\0';
  memset(long_detail, 'b', sizeof(long_detail) - 1U);
  long_detail[sizeof(long_detail) - 1U] = '\0';

  WT_EXPECT_STATUS("a name longer than the table is refused", WT_ERR_LIMIT,
                   wt_cli_report_add(&report, long_name, WT_CLI_RESULT_PASSED, "x"));
  WT_EXPECT_STATUS("and so is a detail", WT_ERR_LIMIT,
                   wt_cli_report_add(&report, "ok", WT_CLI_RESULT_PASSED, long_detail));
  WT_EXPECT_U64("with nothing recorded", 0U, (uint64_t)wt_cli_report_count(&report));
  WT_EXPECT_U64("and both refusals counted", 2U, (uint64_t)wt_cli_report_rejected(&report));

  /* The table is fixed: a report that silently dropped the scenarios past the bound would show a
   * short, clean run. */
  for (i = 0U; i < (size_t)WT_CLI_REPORT_MAX; i++) {
    WT_EXPECT_OK("a scenario fits", wt_cli_report_add(&report, "s", WT_CLI_RESULT_PASSED, ""));
  }
  WT_EXPECT_STATUS("one more is refused", WT_ERR_LIMIT,
                   wt_cli_report_add(&report, "s", WT_CLI_RESULT_PASSED, ""));
  WT_EXPECT_U64("with the table still full rather than short", (uint64_t)WT_CLI_REPORT_MAX,
                (uint64_t)wt_cli_report_count(&report));

  /* A refused row is COUNTED and the exit status fails on it, because the tool's helpers ignore the status a row
   * is added with -- and a name two bytes too long was exactly how a row disappeared from a report while the run
   * still read as green (WT-165). */
  wt_cli_report_init(&report);
  WT_EXPECT_U64("a fresh report has refused nothing", 0U,
                (uint64_t)wt_cli_report_rejected(&report));
  WT_EXPECT_OK("a pass is recorded",
               wt_cli_report_add(&report, "ok", WT_CLI_RESULT_PASSED, "fine"));
  WT_EXPECT_INT("and the run is clean", 0, wt_cli_report_exit_status(&report));
  WT_EXPECT_STATUS("a name past the table is refused", WT_ERR_LIMIT,
                   wt_cli_report_add(&report, long_name, WT_CLI_RESULT_PASSED, "fine"));
  WT_EXPECT_U64("counted rather than dropped", 1U, (uint64_t)wt_cli_report_rejected(&report));
  WT_EXPECT_U64("with the rows that landed still there", 1U,
                (uint64_t)wt_cli_report_count(&report));
  WT_EXPECT_INT("and the run FAILS on it, whatever the rows say", 1,
                wt_cli_report_exit_status(&report));
  {
    FILE *stream = tmpfile();
    char buffer[512];
    size_t read_length;

    WT_EXPECT_TRUE("a stream opens", stream != NULL);
    if (stream != NULL) {
      wt_cli_report_write_text(&report, stream);
      rewind(stream);
      read_length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
      buffer[read_length] = '\0';
      fclose(stream);
      WT_EXPECT_TRUE("and the text report says a row was refused",
                     strstr(buffer, "REFUSED") != NULL);
    }
  }
}

static void test_the_text_report_says_the_same(void) {
  wt_cli_report_t report;
  FILE *stream;
  char buffer[1024];
  size_t read_length;

  wt_cli_report_init(&report);
  WT_EXPECT_OK("a pass is recorded",
               wt_cli_report_add(&report, "varint-boundaries", WT_CLI_RESULT_PASSED, "all forms"));
  WT_EXPECT_OK("and an unattempted scenario",
               wt_cli_report_add(&report, "session-over-udp", WT_CLI_RESULT_UNSUPPORTED, "later"));

  stream = tmpfile();
  WT_EXPECT_TRUE("a stream opens", stream != NULL);
  if (stream != NULL) {
    wt_cli_report_write_text(&report, stream);
    rewind(stream);
    read_length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
    buffer[read_length] = '\0';
    fclose(stream);
    WT_EXPECT_TRUE("the name is there", strstr(buffer, "varint-boundaries") != NULL);
    WT_EXPECT_TRUE("the result is there", strstr(buffer, "unsupported") != NULL);
    WT_EXPECT_TRUE("and the summary counts",
                   strstr(buffer, "1 passed, 0 failed, 1 unsupported") != NULL);
  }
}

int main(void) {
  test_an_unattempted_scenario_is_not_a_pass();
  test_the_report_refuses_rather_than_drops();
  test_the_text_report_says_the_same();
  WT_TEST_MAIN_END("wt_cli_report");
}
