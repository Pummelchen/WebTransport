/* WT-171 over a real connection: a connection ID the peer retires is replaced.
 *
 * The unit test drives the same policy against the library's own pair; this one drives it through the tool's pair
 * -- two runtime sessions with their own connection IDs, an HTTP/3 side behind each handler and a generated
 * identity -- which is what the CLI tools run. The two are not redundant: the defect this round found was in the
 * BOOKKEEPING between the two endpoints, and only a pair with a real peer on the other end can see it.
 */

#ifndef WT_CONFORMANCE_SCENARIO_CONNECTION_IDS_H
#define WT_CONFORMANCE_SCENARIO_CONNECTION_IDS_H

#include <stddef.h>

#include "webtransport/cli/report.h"

/* Keep a spare on both sides, retire the server's on the client, and wait for a replacement. */
wt_cli_result_t wt_scenario_connection_ids_run(int ipv6, char *detail, size_t detail_size);

#endif /* WT_CONFORMANCE_SCENARIO_CONNECTION_IDS_H */
