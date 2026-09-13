/* The connection-control scenarios: GOAWAY, the peer's control stream and the QPACK limits (Phase 10).
 *
 * These mirror the Swift conformance suite's "HTTP/3 Control", "Errors and Shutdown" and "Headers and QPACK"
 * groups wherever the C99 layer takes the same decision, and they are in process for the same reason the
 * refusal scenarios are: the value of the scenario is the CODE the peer would be sent, and a code is a value
 * the report can carry.
 */

#ifndef WT_CONFORMANCE_SCENARIO_CONTROL_H
#define WT_CONFORMANCE_SCENARIO_CONTROL_H

#include "webtransport/cli/report.h"

/* Add this tool's connection-control scenarios to the report. */
void wt_scenario_control_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_CONTROL_H */
