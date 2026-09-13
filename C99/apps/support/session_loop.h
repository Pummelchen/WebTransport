/* One-sided session loops for the client and server tools (Phase 9).
 *
 * The conformance tool drives BOTH endpoints in one process, which is how its scenarios stay hermetic. A CLI
 * tool is one side of a real socket pair: `wt-server-c99 --listen` waits for a peer process and
 * `wt-client-c99 --connect` is it. This is that difference as code, and it is shared between the two tools so
 * that "the exchange" means one thing in both.
 *
 * What it does NOT do is decide policy: where to bind or connect, how to judge the peer's certificate, and how
 * long to wait are the caller's, because those are the tool's command line.
 */

#ifndef WT_SUPPORT_SESSION_LOOP_H
#define WT_SUPPORT_SESSION_LOOP_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"
#include "webtransport/tls/self_signed.h"

/* How the peer is reached (client) or bound (server). The host is a numeric loopback address, which is what the
 * local-development trust mode allows and what a local session needs. */
#define WT_LOOP_HOST_MAX 64U

typedef struct wt_loop_config {
  char host[WT_LOOP_HOST_MAX];
  uint16_t port; /* 0 on the server means "the system chooses" */
  const char *authority;
  const char *path;
  uint64_t timeout_ms;
  int datagram;  /* 0: a WebTransport stream carries the message; 1: a datagram */
  const char *message;
  /* The server's identity, and the pin the client checks it against. Exactly one of the two is used per side. */
  const wt_tls_self_signed_t *identity;
  const uint8_t *pin; /* WT_SHA256_LEN bytes, or NULL for the loopback development bypass */
} wt_loop_config_t;

typedef struct wt_loop_result {
  int established;
  int connect_accepted;
  uint32_t status;         /* the response's :status, 0 when none arrived */
  size_t received_bytes;   /* what the peer sent, in either mode */
  int received_datagram;
  uint16_t bound_port;     /* the server's actual port, which the caller may need to print or use */
} wt_loop_result_t;

/* Wait for one session, accept its CONNECT, answer it, and exchange one message. */
wt_status_t wt_loop_run_server(const wt_loop_config_t *config, wt_loop_result_t *out);

/* Connect, send the CONNECT, wait for the response, and exchange one message. */
wt_status_t wt_loop_run_client(const wt_loop_config_t *config, wt_loop_result_t *out);

/* A stable name for the status a loop returned, for a tool's own message. */
const char *wt_loop_status_name(wt_status_t status);

#endif /* WT_SUPPORT_SESSION_LOOP_H */
