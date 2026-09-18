/* QUIC frame codec. See webtransport/quic/frame.h. */

#include "webtransport/quic/frame.h"

#include "webtransport/checked.h"

#include "webtransport/endian.h"
#include <string.h>

#include "webtransport/quic/frame.h"

const char *wt_quic_frame_kind_name(wt_quic_frame_type_t kind) {
  switch (kind) {
    case WT_QUIC_FRAME_KIND_PADDING:
      return "padding";
    case WT_QUIC_FRAME_KIND_PING:
      return "ping";
    case WT_QUIC_FRAME_KIND_ACK:
      return "ack";
    case WT_QUIC_FRAME_KIND_RESET_STREAM:
      return "reset-stream";
    case WT_QUIC_FRAME_KIND_STOP_SENDING:
      return "stop-sending";
    case WT_QUIC_FRAME_KIND_CRYPTO:
      return "crypto";
    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
      return "new-token";
    case WT_QUIC_FRAME_KIND_STREAM:
      return "stream";
    case WT_QUIC_FRAME_KIND_MAX_DATA:
      return "max-data";
    case WT_QUIC_FRAME_KIND_MAX_STREAM_DATA:
      return "max-stream-data";
    case WT_QUIC_FRAME_KIND_MAX_STREAMS:
      return "max-streams";
    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
      return "data-blocked";
    case WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED:
      return "stream-data-blocked";
    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
      return "streams-blocked";
    case WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID:
      return "new-connection-id";
    case WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID:
      return "retire-connection-id";
    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
      return "path-challenge";
    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
      return "path-response";
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
      return "connection-close";
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
      return "connection-close-application";
    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
      return "handshake-done";
    case WT_QUIC_FRAME_KIND_RESET_STREAM_AT:
      return "reset-stream-at";
    case WT_QUIC_FRAME_KIND_DATAGRAM:
      return "datagram";
    default:
      return "unknown";
  }
}
