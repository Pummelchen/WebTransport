/* The session's own capsules, exercised over a real connection (WT-164). */

#ifndef WT_CONFORMANCE_SCENARIO_CAPSULES_H
#define WT_CONFORMANCE_SCENARIO_CAPSULES_H

#include "webtransport/cli/report.h"

/* Add the CONNECT-stream capsule scenarios to the report. */
void wt_scenario_capsules_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_CAPSULES_H */
