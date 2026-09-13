/* The refusal scenarios: what the endpoint REFUSES, and with which code (Phase 10).
 *
 * The Swift conformance suites are half negative -- a request for the wrong path, a CONNECT for another
 * protocol, a capsule over the bound, a stream for another session -- and the C99 tool had only the positive
 * side. These run in process and without sockets, because a refusal is a decision rather than a session: the
 * value of the scenario is the CODE the peer would be sent, and that is a value the report can carry.
 */

#ifndef WT_CONFORMANCE_SCENARIO_REFUSALS_H
#define WT_CONFORMANCE_SCENARIO_REFUSALS_H

#include "webtransport/cli/report.h"

/* Add this tool's refusal scenarios to the report. */
void wt_scenario_refusals_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_REFUSALS_H */
