/* The sub-protocol negotiation scenario: `wt-protocol` in both directions (Phase 10).
 *
 * The Swift suite asks this as `protocol-structured-fields`, and until this round the C99 tree had no code for
 * it at all, so the scenario is the point at which the feature stops being a module and becomes something a
 * session does: a client offers a list, the server selects one, and the client checks the answer against what
 * it offered -- all through the field section, encoded and decoded, rather than by comparing structures.
 *
 * It is in process for the same reason the refusal scenarios are: what is being asserted is the VALUE that
 * crosses, and a value is something a report can carry.
 */

#ifndef WT_CONFORMANCE_SCENARIO_PROTOCOL_H
#define WT_CONFORMANCE_SCENARIO_PROTOCOL_H

#include "webtransport/cli/report.h"

/* Add this tool's sub-protocol negotiation scenario to the report. */
void wt_scenario_protocol_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_PROTOCOL_H */
