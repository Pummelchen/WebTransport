/* The session scenarios: two endpoints in one process, over loopback (Phase 9).
 *
 * The plan's first completion criterion for the tools is that they "run local IPv4 and IPv6 packet sessions",
 * and this is that criterion as a scenario: a client and a server session inside one process, a real TLS 1.3
 * handshake inside QUIC, an extended CONNECT, the response, a message on a stream and a message as a datagram.
 *
 * It is one process because the tool has no threads and needs none: both endpoints are pumped from one loop,
 * which is exactly how the library's own pair test drives them and how a two-terminal demo behaves once the
 * packets are on the wire. The identity is GENERATED (tls/self_signed.h) and pinned, so the scenario needs no
 * certificate files and no test fixtures -- a conformance tool that depended on the repository's test data would
 * not be runnable where it matters.
 */

#ifndef WT_CONFORMANCE_SCENARIO_SESSION_H
#define WT_CONFORMANCE_SCENARIO_SESSION_H

#include <stddef.h>

#include "webtransport/cli/report.h"

/* Run the whole exchange over the given family and report what happened. `detail` is filled with either the
 * exchange's outcome or the reason it could not be attempted -- a machine with no IPv6 loopback reports
 * `unsupported` with that reason rather than a failure of the code. */
wt_cli_result_t wt_scenario_session_run(int ipv6, char *detail, size_t detail_size);

#endif /* WT_CONFORMANCE_SCENARIO_SESSION_H */
