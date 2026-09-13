/* Two endpoints in one process, over loopback: the harness the scenarios share (WT-160).
 *
 * The session scenario stood a whole pair up inline -- sockets, an identity, transport parameters, both runtimes,
 * both HTTP/3 sides and the handshake, in one ~200-line function -- so a second scenario that needed a pair (and
 * every refusal scenario that wants to assert what the PEER is told does) had no way to reach one without a second
 * copy. This is that setup, factored: `scenario_pair_open` leaves a handshaken pair ready for a scenario to drive,
 * and `scenario_pair_close` is the one teardown.
 *
 * The one process is not a shortcut but the tool's shape: it has no threads and needs none, and both endpoints
 * pumped from one loop is exactly how the library's own pair test drives them.
 */

#ifndef WT_CONFORMANCE_SCENARIO_PAIR_H
#define WT_CONFORMANCE_SCENARIO_PAIR_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cli/report.h"
#include "webtransport/http3/driver.h"
#include "webtransport/runtime/session.h"
#include "webtransport/tls/self_signed.h"

/* Both loops are bounded, and the bound is the tool's own: a scenario that does not finish says so as a FAILURE
 * rather than hanging the suite. The wait is what keeps a loop from spinning faster than loopback delivers. */
#define WT_SCENARIO_TIMEOUT_ROUNDS 400U
#define WT_SCENARIO_WAIT_MICROS 2000U

/* What each side records: the field section it assembles, the frames it was asked about, and the session bytes and
 * datagrams it receives. The driver reports streams in pieces and buffers nothing, so the side that owns the memory
 * assembles them -- here, the harness. */
typedef struct scenario_side {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  uint8_t section[2048];
  size_t section_length;
  int section_complete;
  uint64_t request_stream_id;
  unsigned frames_seen;
  uint64_t control_frames;
  uint8_t stream_data[128];
  size_t stream_bytes;
  uint8_t datagram[256];
  size_t datagram_bytes;
  unsigned datagrams;
} scenario_side_t;

typedef struct scenario_pair {
  wt_udp_socket_t client_socket;
  wt_udp_socket_t server_socket;
  wt_udp_address_t client_address;
  wt_udp_address_t server_address;
  wt_runtime_session_t client;
  wt_runtime_session_t server;
  wt_tls_self_signed_t identity;
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  scenario_side_t client_side;
  scenario_side_t server_side;
  /* The authority the client's certificate names and the CONNECT asks for, which differs by family ("127.0.0.1"
   * or "[::1]"). A scenario that validates the request needs the same string the policy holds. */
  char authority[64];
  uint64_t now;
} scenario_pair_t;

/* A scenario's detail string, which is either the outcome or the reason it could not be attempted. */
void scenario_detail_set(char *detail, size_t size, const char *text);

/* Arm both sides: the HTTP/3 layers, their sinks, the frame handlers, the driver-to-connection binding, the
 * sockets with a generated and pinned identity, the transport parameters (the LIBRARY's, so a mandatory one cannot
 * be forgotten here), both runtimes, and the handshake.
 *
 * WT_CLI_RESULT_FAILED when any of it fails, with `detail` naming which step; WT_CLI_RESULT_UNSUPPORTED when the
 * machine has no loopback for the family asked for. On failure the pair is already torn down, so a caller only
 * closes it on success. */
wt_cli_result_t scenario_pair_open(scenario_pair_t *pair, int ipv6, char *detail, size_t detail_size);

/* Pump both sides once. The sockets are WAITED on first: a non-blocking receive finds nothing until the packet has
 * arrived, and a loop that spun faster than loopback would finish before the first Initial packet did. */
void scenario_pump_once(scenario_pair_t *pair);

/* Clear both sessions and close both sockets. Safe to call on a pair that never opened. */
void scenario_pair_close(scenario_pair_t *pair);

#endif /* WT_CONFORMANCE_SCENARIO_PAIR_H */
