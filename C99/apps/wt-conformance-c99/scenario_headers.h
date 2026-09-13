/* The Headers and QPACK scenarios: the positive side of the field section (Phase 10).
 *
 * The Swift conformance suite's "Headers and QPACK" group drives a CONNECT request and its response through
 * QPACK, then the static, literal and Huffman representations. The C99 report had the NEGATIVE QPACK side (a
 * section needing a table that was never advertised is refused) and no positive one, so a broken encoder would
 * have shown up only in the session scenarios, where the failure arrives as "the CONNECT did not decode".
 */

#ifndef WT_CONFORMANCE_SCENARIO_HEADERS_H
#define WT_CONFORMANCE_SCENARIO_HEADERS_H

#include "webtransport/cli/report.h"

/* Add this tool's header and QPACK scenarios to the report. */
void wt_scenario_headers_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_HEADERS_H */
