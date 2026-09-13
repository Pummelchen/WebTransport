/* A listening peer that misbehaves after a handshake, for the tools' refusal path (WT-147). See the .c file for
 * what each act is and why the misbehaviour is a capability of the test peer rather than a flag on a shipped
 * server.
 *
 * `address` is host:port to bind (port 0 asks the system for one, which is printed); `act` names the act and is
 * refused by the options parser if unknown. `detail` receives either the outcome or the reason the act was not
 * performed -- a peer that never handshook is not the same result as a peer whose frame was ignored. */

#ifndef WT_CONFORMANCE_HOSTILE_PEER_H
#define WT_CONFORMANCE_HOSTILE_PEER_H

#include <stddef.h>

#include "webtransport/cli/report.h"

wt_cli_result_t wt_scenario_hostile_peer_run(const char *address, const char *act, char *detail,
                                             size_t detail_size);

#endif /* WT_CONFORMANCE_HOSTILE_PEER_H */
