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
  int datagram; /* 0: a WebTransport stream carries the message; 1: a datagram */
  /* SERVER only: validate the client's address with a Retry before starting a session on it (RFC 9000 section
   * 8.1.2, WT-168). Off by default, because a Retry costs the client a round trip and is a policy about a
   * listener's exposure rather than something a protocol requires. */
  int retry;
  /* CLIENT only: send the message BEFORE the CONNECT rather than after the response, which is the single flight
   * draft-16 section 4.6 describes ("clients can ... send ... multiple WebTransport CONNECT requests,
   * WebTransport data streams, and WebTransport datagrams all within a single flight"). It is the only order in
   * which a server has something to park, so it is what reaches that path from the tools (WT-189). */
  int early_stream;
  const char *message;
  /* CLIENT only: which `:protocol` token the CONNECT carries, as the `wt_webtransport_upgrade_token_t` value
   * (0 is the draft-16 default, 1 the pre-draft token) -- an int so this header does not depend on the HTTP/3
   * headers, the same shape `trust` uses. The client cannot negotiate the token and a pre-draft peer refuses the
   * session before any SETTINGS exchange, so the tool is told which one to send (F-02b). */
  int upgrade_token;
  /* The server's identity, and the pin the client checks it against. Exactly one of the two is used per side. */
  const wt_tls_self_signed_t *identity;
  const uint8_t *pin; /* WT_SHA256_LEN bytes, or NULL for the loopback development bypass */
  /* CLIENT only: the `wt_tls_trust_mode_t` to validate the peer with, as an int so this header does not depend
   * on the TLS headers. 0 is the loopback development bypass. It exists because the CLI accepted `--trust
   * system`, reported it, and then always took the bypass: the option was wired to nothing (WT-193). */
  int trust;
} wt_loop_config_t;

/* What the CLIENT decided about the response (WT-155). The server's report names why it refused a CONNECT --
 * `requestOutcome` and `h3Error` -- and the other direction had nothing to say: a peer that answered 404 and a
 * peer that answered a field section this layer refused both produced `"status":"timeout"`, because the tool
 * returned before recording why. One number a JSON reader can switch on, and the HTTP/3 error beside it when the
 * RESPONSE ITSELF was refused, which is the failure no status can express. */
typedef enum wt_loop_response_outcome {
  WT_LOOP_RESPONSE_NONE = 0,     /* no response was decoded */
  WT_LOOP_RESPONSE_ACCEPTED = 1, /* a 2xx response: the session is established */
  WT_LOOP_RESPONSE_NOT_ACCEPTED =
      2, /* a status that is not 2xx, which this client will not treat as a session */
  WT_LOOP_RESPONSE_REFUSED =
      3 /* the HTTP/3 layer refused the response; `h3_error` names the rule */
} wt_loop_response_outcome_t;

typedef struct wt_loop_result {
  int established;
  int connect_accepted;
  uint32_t status;       /* the response's :status, 0 when none arrived */
  size_t received_bytes; /* what the peer sent, in either mode */
  int received_datagram;
  /* Whether the message went out BEFORE the CONNECT (WT-189), so a report says which order the run used. */
  int early_stream_sent;
  uint16_t bound_port; /* the server's actual port, which the caller may need to print or use */
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
  /* What THIS endpoint's own close said, when it closed one. `close_code` above is the hint a refusing handler
   * leaves and the connection clears once used, so it reads as zero whether or not a close was sent; this is the
   * close itself -- kind, code and frame type -- plus the status of the handler that refused. A run that ended
   * with this endpoint having closed did NOT end well, whatever the exchange counters say (WT-144). */
  /* Why a CONNECT was refused: the outcome the session layer decided and the HTTP/3 error it named. The tool
   * returned a bare WT_ERR_PROTOCOL for every refusal before -- "not WebTransport", "not this authority", "no
   * WT_ENABLED" and "missing :scheme" all looked alike, and a third-party client's request was diagnosed by
   * reading the validator rather than by running the server (WT-153). */
  /* What the CONNECT asked for, as the server decoded it: "METHOD PROTOCOL AUTHORITY PATH". A refusal says
   * "not WebTransport" or "not this authority" and nothing about the request that produced it, so a third-party
   * client's CONNECT could only be diagnosed by reading the validator (WT-153). */
  char request_line[192];
  unsigned request_outcome;
  /* The client's side of the same reporting (WT-155): what it decided about the response, and the HTTP/3 error
   * when the response was refused. Both directions now answer "why did this session not come up". */
  unsigned response_outcome;
  unsigned long long request_status;
  unsigned long long h3_error;
  unsigned close_kind;
  uint64_t close_sent_error_code;
  uint64_t close_sent_frame_type;
  wt_status_t close_cause;
  uint64_t close_cause_frame;
  /* Whether that close was actually SENT to the peer. The idle timeout closes silently (RFC 9000 section 10.1),
   * so the fields above are set either way and only this says whether the peer was told -- which is the
   * difference between a session this endpoint ended and one it merely stopped (WT-144, WT-145). */
  int close_was_sent;
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
  /* How many of this endpoint's packets the PEER acknowledged, by space, and how many are still in flight. The
   * pair distinguishes "the peer is not reading us" from "the peer reads us and does not answer", which no other
   * counter can: a space with packets sent, none lost and none acknowledged is a peer that never processed them
   * (WT-145). */
  unsigned acked_initial;
  unsigned acked_handshake;
  unsigned acked_application;
  unsigned in_flight;
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
  /* What the peer's CONNECT-stream CAPSULES carried (draft-16 section 5). The session's flow control arrives
   * there, and before WT-164 this endpoint parsed those bytes as HTTP/3 frames: a flow-control grant's type is an
   * unknown frame type, so its length was read as a frame length and the grant was dropped without a word. These
   * fields are the fact that says it was not dropped -- `peer_max_data` is the send limit the peer granted, and
   * `peer_close_code` is the application code it ended the session with, which a transport-level report cannot
   * show because a session close leaves the connection open. */
  int peer_max_data_set;
  uint64_t peer_max_data;
  int peer_drained;
  int peer_close_code_set;
  uint32_t peer_close_code;
  /* How many capsules this endpoint REFUSED, and the HTTP/3 code it closed the connection over when it did. A
   * capsule the peer sent that this endpoint could not accept is a fact about the run, and without the code the
   * refusal reads as an unexplained INTERNAL_ERROR (WT-165). */
  unsigned capsules_refused;
  uint64_t capsule_error;
} wt_loop_result_t;

/* Wait for one session, accept its CONNECT, answer it, and exchange one message. */
wt_status_t wt_loop_run_server(const wt_loop_config_t *config, wt_loop_result_t *out);

/* Connect, send the CONNECT, wait for the response, and exchange one message. */
wt_status_t wt_loop_run_client(const wt_loop_config_t *config, wt_loop_result_t *out);

/* A stable name for the status a loop returned, for a tool's own message. */
const char *wt_loop_status_name(wt_status_t status);

#endif /* WT_SUPPORT_SESSION_LOOP_H */
