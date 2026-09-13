/* The refusal that reaches the PEER, over a real connection (WT-159, WT-160).
 *
 * The refusal scenarios are decisions rather than sessions -- they call the validator and assert the code a peer
 * WOULD be sent -- and this one exists because that is a different claim from the code a peer IS sent. The chain is
 * three layers long: the frame arrives through the connection, the HTTP/3 driver refuses it with an HTTP/3 error
 * code, and the driver states that refusal as an APPLICATION close. Nothing drove the whole of it until the
 * runtime pair test did (WT-159), and the same claim belongs in this tool: it is the layer a scenario can assert
 * both ENDS of.
 */

#ifndef WT_CONFORMANCE_SCENARIO_REFUSAL_WIRE_H
#define WT_CONFORMANCE_SCENARIO_REFUSAL_WIRE_H

#include "webtransport/cli/report.h"

/* Add this tool's on-the-wire refusal scenarios to the report. */
void wt_scenario_refusal_wire_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_REFUSAL_WIRE_H */
