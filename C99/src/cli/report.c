/* Machine-readable scenario results (Phase 9). */

#include "webtransport/cli/report.h"

#include <string.h>

void wt_cli_report_init(wt_cli_report_t *report) {
  if (report == NULL) return;
  report->count = 0U;
}

const char *wt_cli_result_name(wt_cli_result_t result) {
  switch (result) {
    case WT_CLI_RESULT_PASSED: return "passed";
    case WT_CLI_RESULT_FAILED: return "failed";
    case WT_CLI_RESULT_UNSUPPORTED: return "unsupported";
  }
  return "unknown";
}

wt_status_t wt_cli_report_add(wt_cli_report_t *report, const char *scenario, wt_cli_result_t result,
                              const char *detail) {
  wt_cli_scenario_t *slot;

  if (report == NULL || scenario == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (strlen(scenario) >= (size_t)WT_CLI_SCENARIO_NAME_MAX) return WT_ERR_LIMIT;
  if (detail != NULL && strlen(detail) >= (size_t)WT_CLI_SCENARIO_DETAIL_MAX) return WT_ERR_LIMIT;
  if (report->count >= WT_CLI_REPORT_MAX) return WT_ERR_LIMIT;

  slot = &report->scenarios[report->count];
  memset(slot, 0, sizeof(*slot));
  memcpy(slot->name, scenario, strlen(scenario) + 1U);
  if (detail != NULL) memcpy(slot->detail, detail, strlen(detail) + 1U);
  slot->result = result;
  report->count++;
  return WT_OK;
}

size_t wt_cli_report_count(const wt_cli_report_t *report) {
  if (report == NULL) return 0U;
  return report->count;
}

size_t wt_cli_report_count_of(const wt_cli_report_t *report, wt_cli_result_t result) {
  size_t i;
  size_t total = 0U;

  if (report == NULL) return 0U;
  for (i = 0U; i < report->count; i++) {
    if (report->scenarios[i].result == result) total++;
  }
  return total;
}

int wt_cli_report_exit_status(const wt_cli_report_t *report) {
  if (report == NULL) return 1;
  if (wt_cli_report_count_of(report, WT_CLI_RESULT_FAILED) > 0U) return 1;
  if (wt_cli_report_count_of(report, WT_CLI_RESULT_UNSUPPORTED) > 0U) return 3;
  return 0;
}

/* A JSON string with the two characters that can appear in these messages escaped. The names and
 * details are this tool's own text, so this is a guard against a message containing a quote or a
 * backslash rather than a general-purpose escaper. */
static void write_json_string(FILE *stream, const char *text) {
  size_t i;

  fputc('"', stream);
  for (i = 0U; text[i] != '\0'; i++) {
    if (text[i] == '"' || text[i] == '\\') fputc('\\', stream);
    fputc(text[i], stream);
  }
  fputc('"', stream);
}

void wt_cli_report_write_json(const wt_cli_report_t *report, FILE *stream) {
  size_t i;

  if (report == NULL || stream == NULL) return;
  fputs("{\"scenarios\":[", stream);
  for (i = 0U; i < report->count; i++) {
    if (i > 0U) fputc(',', stream);
    fputs("{\"name\":", stream);
    write_json_string(stream, report->scenarios[i].name);
    fputs(",\"result\":", stream);
    write_json_string(stream, wt_cli_result_name(report->scenarios[i].result));
    fputs(",\"detail\":", stream);
    write_json_string(stream, report->scenarios[i].detail);
    fputc('}', stream);
  }
  fprintf(stream, "],\"summary\":{\"total\":%llu,\"passed\":%llu,\"failed\":%llu,\"unsupported\":%llu}}\n",
          (unsigned long long)report->count,
          (unsigned long long)wt_cli_report_count_of(report, WT_CLI_RESULT_PASSED),
          (unsigned long long)wt_cli_report_count_of(report, WT_CLI_RESULT_FAILED),
          (unsigned long long)wt_cli_report_count_of(report, WT_CLI_RESULT_UNSUPPORTED));
}

void wt_cli_report_write_text(const wt_cli_report_t *report, FILE *stream) {
  size_t i;

  if (report == NULL || stream == NULL) return;
  for (i = 0U; i < report->count; i++) {
    fprintf(stream, "%-32s %-12s %s\n", report->scenarios[i].name,
            wt_cli_result_name(report->scenarios[i].result), report->scenarios[i].detail);
  }
  fprintf(stream, "%llu scenario(s): %llu passed, %llu failed, %llu unsupported\n",
          (unsigned long long)report->count,
          (unsigned long long)wt_cli_report_count_of(report, WT_CLI_RESULT_PASSED),
          (unsigned long long)wt_cli_report_count_of(report, WT_CLI_RESULT_FAILED),
          (unsigned long long)wt_cli_report_count_of(report, WT_CLI_RESULT_UNSUPPORTED));
}
