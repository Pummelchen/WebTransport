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
  /* The first error the runtime recorded while RECEIVING, and how many there were. The status a failed run
   * returns is the tool's own ("timeout"), which says the handshake did not finish and nothing about why; this
   * is the layer that knows -- and without it a peer that answers with something this endpoint rejects looks
   * exactly like a peer that never answered (WT-135). */
  wt_status_t first_receive_error;
  unsigned receive_errors;
  /* How many packets the connection SAW, and what its last receive call returned. A stall has two shapes --
   * "nothing arrived" and "things arrived and were not consumed" -- and they look the same from the tool's
   * status alone (WT-135). */
  unsigned packets_seen;
  wt_status_t last_receive;
  /* WHICH rule refused, not just that something did. The connection records the code its own refusal names and
   * the frame type it blames, and the code the PEER sent when it closed -- so a protocol error names the rule
   * instead of sending the next round hunting for it in four candidate checks (WT-135). */
  uint64_t close_code;
  uint64_t close_frame_type;
  int close_code_set;
  uint64_t peer_error_code;
  int peer_closed;
  /* How many datagrams/packets the receive loop DISCARDED rather than parsed. A discard is ordinary during a
   * handshake (a packet for a key level this endpoint does not have yet, an unauthenticated packet) and it is
   * exactly what a refusal is NOT: a run whose packets are all discarded needs keys, and a run that refuses
   * needs a parser (WT-135). */
  uint64_t packets_discarded;
  /* Whether the connection holds RECEIVE keys for each packet-number space. This is the one fact that says where
   * a stalled handshake stopped: Initial keys without Handshake keys means the ClientHello went out and the
   * ServerHello was never processed, so the peer's encrypted flight is correctly discarded and no parser can be
   * at fault (WT-135). */
  int has_initial_keys;
  int has_handshake_keys;
  int has_application_keys;
  /* What the handshake's own state machine says. Keys installed and the state not CONNECTED is the shape of a
   * flight that was READ but not completed -- and the two facts together are what a diagnosis needs (WT-135). */
  const char *handshake_state;
  /* How many lost-frame reports were answered by resending the request (WT-135). */
  unsigned resends;
  /* Probe timeouts that fired, summed over the spaces, and how many carried an outstanding frame. */
  unsigned probes;
  unsigned probes_with_data;
  /* Packets sent per space: initial, handshake, application. */
  unsigned sent_initial;
  unsigned sent_handshake;
  unsigned sent_application;
  /* The TYPE BYTES of the messages this endpoint absorbed into its TLS transcript, in order. The list must be
   * RFC 8446's (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished) and
   * nothing else -- a transcript that hashed something extra is invisible to a pair of the same code and fatal
   * to a peer that hashes the RFC's list (WT-135). `transcript_types_length` is how many are recorded. */
  /* ACK frames sent per space and the largest packet number each named: initial, handshake, application. */
  unsigned acks_initial;
  unsigned acks_handshake;
  unsigned acks_application;
  unsigned long long ack_largest_initial;
  unsigned long long ack_largest_handshake;
  unsigned long long ack_largest_application;
  uint8_t transcript_types[16];
  size_t transcript_types_length;
  /* The stream id the driver opened for the request, and how many streams this endpoint opened in each class: a
   * data stream's class is what says whether a peer can answer it, and the id is the only thing that says which
   * it is (WT-135). */
  uint64_t request_stream_id;
  unsigned streams_opened_bidi;
  unsigned streams_opened_uni;
} wt_loop_result_t;

/* Wait for one session, accept its CONNECT, answer it, and exchange one message. */
wt_status_t wt_loop_run_server(const wt_loop_config_t *config, wt_loop_result_t *out);

/* Connect, send the CONNECT, wait for the response, and exchange one message. */
wt_status_t wt_loop_run_client(const wt_loop_config_t *config, wt_loop_result_t *out);

/* A stable name for the status a loop returned, for a tool's own message. */
const char *wt_loop_status_name(wt_status_t status);

#endif /* WT_SUPPORT_SESSION_LOOP_H */
