# draft-ietf-webtrans-http3-16 compliance matrix (C99)

What the draft requires, where this tree implements it, and which test exercises it. Every symbol named here is
checked by `scripts/check-matrix.sh`, which greps this file for identifiers and fails if one is not in the tree --
so the matrix cannot drift away from the code without a build saying so.

Statuses: **tested** means a test exercises the behaviour end to end or at the interface; **partial** means the
behaviour exists with a recorded edge; **--** means the layer is deliberately not this tree's.

| # | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| 3.1 | A WebTransport session starts with an extended CONNECT carrying `:protocol = webtransport` | `wt_webtransport_session_request_validate`, `WT_WEBTRANSPORT_PROTOCOL_TOKEN` | `test_webtransport_session_request`, `wt_conformance_scenarios` | tested |
| 3.1 | A server that did not advertise WebTransport refuses the session | `wt_webtransport_request_policy_t`, `WT_HTTP3_SETTING_WT_ENABLED` | `test_webtransport_session_request` | tested |
| 3.1 | Both roles advertise the reliable-stream-reset extension WebTransport requires, with the empty value that makes it a flag | `WT_QUIC_TP_RESET_STREAM_AT`, `wt_quic_transport_parameters_build` | `test_quic_transport_parameters`, `test_quic_peer_limits` | tested |
| 3.1 | A path or authority the server does not serve is refused with a status | `WT_WEBTRANSPORT_REJECT_NOT_FOUND`, `wt_webtransport_session_request_validate` | `test_webtransport_session_request` | tested |
| 3.2 | A successful session is answered with a 2xx response on the same stream | `wt_http3_driver_send_response`, `wt_http3_endpoint_on_response_headers` | `test_runtime_session_pair`, `wt_conformance_scenarios` | tested |
| 3.2 | A refusal is answered with a non-2xx status and no session exists | `wt_http3_message_encode` (response form) | `test_http3_endpoint`, `test_webtransport_session_request` | tested |
| 4.1 | A session IS a request stream, and its state machine follows the request rules | `wt_http3_endpoint_open_request`, `wt_http3_request_on_frame` | `test_http3_endpoint`, `test_http3_request` | tested |
| 4.1 | Trailers may not carry pseudo-header fields | `wt_http3_endpoint_on_request_headers` | `test_http3_endpoint` | tested |
| 4.2 | WebTransport streams are prefixed with their type and the session ID | `wt_webtransport_stream_prefix_write`, `wt_webtransport_stream_prefix_parse` | `test_webtransport_framing`, `test_http3_driver` | tested |
| 4.2 | A bidirectional WebTransport stream is classified apart from an HTTP/3 request | `wt_http3_driver_classify_bidi_start` | `test_http3_driver` | tested |
| 4.2 | A prefix that arrives in pieces is assembled, and replayed for a request | `wt_http3_driver_on_quic_frame`, `wt_http3_driver_pending_t` | `test_http3_driver` | tested |
| 4.2 | A stream naming another session is refused with H3_ID_ERROR | `wt_http3_driver_set_session_id` | `test_http3_driver` | tested |
| 4.2 | The peer's unidirectional stream table is bounded and refuses with no error code | `WT_HTTP3_ENDPOINT_STREAMS_MAX`, `wt_http3_endpoint_on_uni_stream` | `test_http3_limits` | tested |
| 4.3 | Datagrams carry a quarter stream ID and then the session's payload | `wt_webtransport_datagram_write`, `wt_webtransport_datagram_parse` | `test_webtransport_framing`, `wt_cli_session_datagram` | tested |
| 4.3 | Datagram support is advertised before a peer may send one | `WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE` | `test_runtime_session_pair` | tested |
| 4.4 | A WebTransport application error is remapped into the `WT_APPLICATION_ERROR` range, with HTTP/3's reserved codepoints skipped | `wt_webtransport_error_to_http3`, `wt_webtransport_error_from_http3`, `WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST` | `test_webtransport_error` | tested |
| 4.4 | A codepoint outside that range, or one of the reserved codepoints inside it, is not an application error | `wt_webtransport_error_is_application_range`, `wt_webtransport_error_from_http3` | `test_webtransport_error` | tested |
| 4.6 | A stream or datagram that arrives before the session it names is buffered until it can be associated, with a bound on how much | `wt_webtransport_buffered_t`, `wt_http3_driver_data_stream_session_id`, `wt_http3_driver_open_session_stream` | `test_webtransport_buffered`, `test_runtime_session_pair`, `wt_cli_early_stream` | tested |
| 4.6 | A buffered stream over the bound is closed with `WT_BUFFERED_STREAM_REJECTED` | `wt_http3_driver_reject_data_stream`, `WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED` | `test_runtime_session_pair` | tested |
| 4.6 | A buffered datagram over the bound is dropped, and a parked item that names another session is dropped rather than refused | `wt_webtransport_buffered_park_datagram`, `wt_webtransport_buffered_drain_datagrams` | `test_webtransport_buffered`, `wt_cli_early_stream_datagram` | tested |
| 4.4 | The PROTOCOL error codes the draft registers travel unmapped, because they are HTTP/3 codes rather than application ones | `WT_WEBTRANSPORT_ERROR_SESSION_GONE`, `WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED` | `test_webtransport_error` | tested |
| 4.3 | A datagram that does not hold its quarter ID is malformed rather than short | `wt_webtransport_datagram_parse` | `test_webtransport_framing`, `test_http3_malformed` | tested |
| 5 | Capsules are the session's control channel on the CONNECT stream | `wt_webtransport_capsule_decode`, `wt_webtransport_capsule_encode` | `test_webtransport_capsule` | tested |
| 5.1 | WT_MAX_DATA / WT_MAX_STREAM_DATA / WT_MAX_STREAMS strictly increase | `wt_webtransport_flow_on_max_data`, `wt_webtransport_flow_on_max_streams` | `test_webtransport_flow` | tested |
| 5.1 | A stream count above the draft's 2^60 ceiling is a flow-control error | `WT_WEBTRANSPORT_MAX_STREAMS_VALUE` | `test_webtransport_flow` | tested |
| 5.1 | Flow control is enabled by SETTINGS and applies to what this endpoint sends | `wt_session_flow_advertised`, `wt_session_flow_configure` | `test_api_flow` | tested |
| 5.1 | The limits an endpoint advertises are the ones it enforces | `wt_runtime_session_advertise` | `test_runtime_session_pair` | tested |
| 5.2 | WT_DRAIN_SESSION stops new streams and lets existing ones finish | `wt_webtransport_session_on_drain`, `wt_webtransport_drain_session_write` | `test_webtransport_session`, `test_api_session` | tested |
| 5.4 | WT_CLOSE_WEBTRANSPORT_SESSION carries the first close's code | `wt_webtransport_session_on_close`, `wt_webtransport_close_session_parse` | `test_webtransport_session` | tested |
| 5.4 | A close reason above the draft's ceiling is refused | `WT_CAPSULE_CLOSE_MAX_REASON` | `test_webtransport_capsule` | tested |
| 9.5 | The five error codes the draft registers in HTTP/3's registry carry their registered values | `WT_WEBTRANSPORT_ERROR_FLOW_CONTROL`, `WT_WEBTRANSPORT_ERROR_ALPN`, `WT_WEBTRANSPORT_ERROR_REQUIREMENTS_NOT_MET` | `test_webtransport_error` | tested |
| 3.2 | A sub-protocol is negotiated through `wt-protocol`, a Structured Fields list in the request and a string item in the response | `wt_webtransport_protocol_decode_list`, `wt_webtransport_session_request_negotiate`, `wt_webtransport_session_response_selected_protocol`, `wt_webtransport_protocol_write_field` | `test_webtransport_protocol`, `protocol-negotiation`, `protocol-negotiation-required-refusal`, `protocol-negotiation-unoffered-selection` | tested |
| 6 | The CONNECT stream ending ends the session | `wt_webtransport_session_on_stream_end` | `test_webtransport_session` | tested |
| 6 | A terminated session's streams are reset with `WT_SESSION_GONE`, its receive sides aborted, and no new datagram or stream is sent | `wt_http3_driver_end_session_streams`, `wt_webtransport_error_to_http3` | `test_runtime_session_pair` | tested |
| -- | QUIC transport the session runs on | `quic/` (frames, packets, loss, congestion, streams, DATAGRAM) | `test_quic_*`, `test_runtime_session_pair` | tested |
| -- | HTTP/3 the session runs on | `http3/` (frames, SETTINGS, control, request, QPACK, GOAWAY, driver) | `test_http3_*` | tested |
| -- | TLS the session runs on | `tls/` (RFC 8446 schedule, messages, X25519, trust, self-signed) | `test_tls13_*`, `test_tls_self_signed` | tested |
| -- | Server push | -- | -- | -- |
| -- | 0-RTT and resumption | -- | -- | -- |
| -- | Session under a connection that changes its connection ID | -- | -- | partial |

## The two partial rows, stated plainly

- **Server push**: the draft does not use it, and HTTP/3 push is refused deterministically by the endpoint
  (`WT_HTTP3_ID_ERROR` for a client, `WT_HTTP3_STREAM_CREATION_ERROR` for a server) rather than ignored. That is
  a deliberate refusal, not a missing feature.
- **0-RTT and resumption**: the `early_data` and `pre_shared_key` extensions are NOT implemented and not
  exported -- `tls/extension.h` says so, because they need the ticket machinery this tree does not have. The
  draft's rule that a server must refuse REMEMBERED 0-RTT settings that reduce WebTransport capacity therefore
  has nothing to apply to here: there are no remembered settings, and a peer cannot 0-RTT into a session. That
  is a deliberate absence rather than a gap in an implemented feature, and the Swift scenario that asserts the
  rule (`zero-rtt-settings`) is mirrored by it not being reachable.
- **Connection ID changes during a handshake**: the tests use the SAME connection ID at both ends, which is what
  makes the Initial keys -- derived from it -- identical on both sides. A peer that replaces its connection ID
  during the handshake would not be tracked, and this is recorded as the transport gap it is (the tracker's
  connection-ID item) rather than claimed as done. What IS covered, since WT-171, is the change after the
  handshake: `a-retired-connection-id-is-replaced` keeps a spare ID on both ends of a real pair, has the client
  retire the server's, and asserts that the server issues the next sequence and that both connections stay up --
  which is the half a session actually depends on, and the half where the two endpoints' bookkeeping has to
  agree.
