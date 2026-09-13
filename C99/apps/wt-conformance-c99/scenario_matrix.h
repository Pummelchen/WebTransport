/* The interop matrix scenarios: one table, many cases (Phase 10).
 *
 * The Swift suite's "Interop Matrices" group is not a remote test -- it is a fixed table of inputs run against
 * the library in process, and its stream matrix asks the four directions plus the inputs that must be refused.
 * The C99 report had the split-prefix edge and nothing else in that shape, so a routing regression in one
 * direction would have shown up only inside a socket scenario, with no case naming it.
 *
 * The table is data: each case is a name, a call, and what it must produce. The report carries ONE entry with
 * the count, because that is what a matrix is -- and the failing case's name is in the detail, so a red run
 * says which row went wrong rather than that "interop" broke.
 */

#ifndef WT_CONFORMANCE_SCENARIO_MATRIX_H
#define WT_CONFORMANCE_SCENARIO_MATRIX_H

#include "webtransport/cli/report.h"

/* Add this tool's interop matrix scenarios to the report. */
void wt_scenario_matrix_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_MATRIX_H */
