/* Machine-readable scenario results (Phase 9).
 *
 * A conformance tool's output is its product, and the plan asks for one thing from it: a stable
 * machine-readable report. That means three rules, and all three are about NOT lying.
 *
 *   - A scenario that did not run is reported as UNSUPPORTED with a reason, never as a pass and
 *     never as a failure. A tool whose report cannot distinguish "verified" from "not attempted"
 *     is a tool whose green line means nothing.
 *
 *   - The report is ordered and named by the tool, not by the run, so two runs' outputs can be
 *     compared by a script without sorting them first.
 *
 *   - The exit status carries the same information as the report rather than replacing it: a
 *     failure is 1, "nothing failed but something was not attempted" is 3 (the status this
 *     project already uses for a build that cannot do what was asked), and only a full pass is 0.
 */

#ifndef WEBTRANSPORT_CLI_REPORT_H
#define WEBTRANSPORT_CLI_REPORT_H

#include <stddef.h>
#include <stdio.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_cli_result {
  WT_CLI_RESULT_PASSED = 1,
  WT_CLI_RESULT_FAILED = 2,
  WT_CLI_RESULT_UNSUPPORTED = 3
} wt_cli_result_t;

/* The most scenarios one report holds. Fixed, like every other table here: a report that grows
 * with what it is describing cannot be bounded by the caller. */
#define WT_CLI_REPORT_MAX 64U

#define WT_CLI_SCENARIO_NAME_MAX 64U
#define WT_CLI_SCENARIO_DETAIL_MAX 160U

typedef struct wt_cli_scenario {
  char name[WT_CLI_SCENARIO_NAME_MAX];
  char detail[WT_CLI_SCENARIO_DETAIL_MAX];
  wt_cli_result_t result;
} wt_cli_scenario_t;

typedef struct wt_cli_report {
  wt_cli_scenario_t scenarios[WT_CLI_REPORT_MAX];
  size_t count;
} wt_cli_report_t;

void wt_cli_report_init(wt_cli_report_t *report);

/* Record one scenario. A name longer than the table holds is refused rather than truncated: a
 * truncated name is a different scenario. Returns WT_ERR_LIMIT when the report is full. */
wt_status_t wt_cli_report_add(wt_cli_report_t *report, const char *scenario, wt_cli_result_t result,
                              const char *detail);

size_t wt_cli_report_count(const wt_cli_report_t *report);
size_t wt_cli_report_count_of(const wt_cli_report_t *report, wt_cli_result_t result);

/* The names are stable and are what a script matches on. */
const char *wt_cli_result_name(wt_cli_result_t result);

/* The exit status the report implies: 0 when everything passed, 1 when anything failed, 3 when
 * something was not attempted and nothing failed. */
int wt_cli_report_exit_status(const wt_cli_report_t *report);

/* One JSON object: {"scenarios":[{"name":...,"result":...,"detail":...}],"summary":{...}}. */
void wt_cli_report_write_json(const wt_cli_report_t *report, FILE *stream);

/* The same information for a human, one line per scenario. */
void wt_cli_report_write_text(const wt_cli_report_t *report, FILE *stream);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_CLI_REPORT_H */
