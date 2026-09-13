# The public C99 API

`webtransport/webtransport.h` is the header a consumer includes; everything else under
`include/webtransport/` is the machinery it is built from. This document is the contract
for the parts a program is written against, and it says what is NOT there yet as plainly
as what is, because a documented absence is a design decision and an undocumented one is a
bug report waiting to happen.

The API is the consumer's view of draft-ietf-webtrans-http3-16. It is not a protocol
library with a public face bolted on: the layers below (`quic/`, `tls/`, `http3/`,
`webtransport/`) are public too, and a program that wants to drive QUIC itself can. What
the `api/` layer adds is the part a program that just wants WebTransport sessions should
not have to write: a handle with a lifetime, an error surface that cannot leak a peer's
text, a place for events to go, and answers to "may I send this".

## The module map

| Header | What a consumer uses it for |
| --- | --- |
| `api/session.h` | The session handle: create, destroy, state, error, the CONNECT-stream capsules. |
| `api/events.h` | The event-loop seam: the callback table, peer streams, peer datagrams. |
| `api/flow.h` | Backpressure: the peer's flow-control grants and what is left of them. |
| `webtransport.h` | The umbrella, which includes all of the above plus every layer beneath. |

## Endpoints

A session is created for **one authority and one path on one CONNECT stream**:

```c
wt_session_config_t config = wt_session_config_default();
config.authority = "example.com";   /* copied into the handle */
config.path = "/chat";              /* copied into the handle */
config.session_id = 4;              /* the CONNECT stream ID */
```

The strings are copied, so a caller's buffer may go out of scope the moment
`wt_session_create` returns. `session_id` is checked against the quarter stream ID of every
datagram and the session ID in every WebTransport stream prefix, which is what keeps two
sessions on one connection from delivering each other's traffic: a stream or datagram
naming another session is refused with HTTP/3's identifier error, never delivered to the
wrong session and never dropped silently.

`wt_session_config_default()` returns a configuration with every bound at its default, so a
caller overwrites the fields it cares about rather than completing a struct. That is not
politeness: a C caller that sets three fields of a six-field struct passes whatever its
stack held into a bound, and the bounds are what stop a peer from spending this process's
memory.

**Trust is a connection-level policy and is not yet part of this API.** Chain validation,
the CertificateVerify gate and the prompt-free trust modes live in the TLS layer
(`webtransport/tls/...`), and a caller driving a connection uses them there. Surfacing them
here is the next part of this phase; until it lands, this document does not claim a
`trust` field.

## Sessions

```c
wt_session_t *session = NULL;
if (wt_session_create(&config, allocator, &session) != WT_OK) { /* one of four statuses */ }
...
wt_session_destroy(session, allocator);
```

`create` and `destroy` take the SAME allocator, and `NULL` means the default one at both
ends. That is the ownership rule in one line: the object goes back where it came from, and
a caller using a pool or an arena gets its session returned to it rather than to `free`.

The handle is opaque. Its layout is private (`src/api/session_internal.h`), so it can change
between releases without breaking a compiled consumer, and there is no public field to
poke.

### State

| State | Meaning |
| --- | --- |
| `WT_SESSION_ESTABLISHING` | The request was accepted; the response has not gone out. |
| `WT_SESSION_ESTABLISHED` | The response went out: streams and datagrams may flow. |
| `WT_SESSION_DRAINING` | A drain was sent or received: no new streams, existing ones may finish. |
| `WT_SESSION_CLOSED` | A close was sent or received: the session is over. |

The public enum is mapped from the implementation's own member by member, so renumbering
one cannot silently renumber the other.

## The error surface

`wt_session_last_error()` returns a `wt_session_error_t`: a status and a `uint64_t` code,
with no room for a string. That is the design, not an omission. A peer's reason text is the
peer's, and a log line that quotes it is a log-injection and a trust problem; a peer's
*code* is meaningful and travels through unchanged, which is what "a refusal keeps the
peer's code" means at this surface. `wt_session_status_name()` gives a stable name for a
status, for the message a caller writes itself.

## The event loop

The library owns no thread and no queue. Callbacks run inside the call the application made,
on its thread; a callback must not call back into the same session; every pointer a callback
receives is a view into the caller's own buffer, valid for the call only.

```c
wt_session_callbacks_t callbacks = {0};
callbacks.context = &my_state;
callbacks.on_stream_opened = ...;   /* a peer stream, once, before its data */
callbacks.on_stream_data = ...;     /* data, with end_stream on the last one */
callbacks.on_stream_reset = ...;    /* the peer's code, carried through */
callbacks.on_datagram = ...;        /* the payload alone, quarter stream ID stripped */
callbacks.on_drain = ...;           /* the peer is going away */
callbacks.on_close = ...;           /* the peer closed, with its code */
wt_session_set_callbacks(session, &callbacks);
```

**No callback means the event is accepted and discarded**, not refused. A datagram this
endpoint did not ask for is not a peer error, and turning this endpoint's configuration
into a connection error would blame the peer for it. Clearing with
`wt_session_set_callbacks(session, NULL)` stops delivery the same way.

## Streams

```c
wt_session_on_stream_opened(session, stream_id, unidirectional, session_id);
wt_session_on_stream_data(session, stream_id, data, length, end_stream);
wt_session_on_stream_reset(session, stream_id, peer_error_code);
```

The caller reports what the QUIC and HTTP/3 layers saw. A stream whose prefix named another
session, a stream opened twice, and data on a stream that was never opened are all
`WT_ERR_STATE` -- the first is the peer's mistake and carries HTTP/3's identifier error,
the other two are the caller's ordering. Peer streams live in a fixed table of
`WT_SESSION_STREAM_MAX` slots sized by `max_streams`; a stream past the bound is refused
with the excessive-load code, because the table is a bound the peer must run into rather
than a limit that grows with the peer's appetite.

## Datagrams

```c
wt_session_on_datagram(session, bytes, length);   /* as it came off the wire */
```

The bytes are a QUIC DATAGRAM payload: a quarter stream ID and then the session data. The
quarter stream ID must name this session, and the payload must be within
`max_datagram_bytes` (default `WT_SESSION_DATAGRAM_MAX`). A payload over it is refused with
the excessive-load code rather than buffered. A datagram that does not hold its quarter ID
at all is `WT_ERR_PROTOCOL`, because a datagram IS the unit: unlike a stream, there is no
"more is coming" for it.

## Backpressure and flow control

Draft-16 gives the session its own flow control as capsules on the CONNECT stream. The
peer's SETTINGS carry the initial limits, and `wt_session_flow_configure` applies them:

```c
int enabled = wt_session_flow_advertised(&local_settings)
           && wt_session_flow_advertised(&peer_settings);
wt_session_flow_configure(session, enabled, initial_max_data,
                          initial_max_streams_bidi, initial_max_streams_uni);

uint64_t left = wt_session_flow_data_allowance(session);      /* ask first */
if (left >= bytes) wt_session_flow_record_data(session, bytes);
else              /* wait: this is what backpressure means with no socket to block on */;
```

The rules, which are the draft's:

- **Off until both endpoints say otherwise.** While off, a flow-control capsule is ignored
  rather than refused, and nothing is counted.
- **Limits strictly increase.** A capsule at or below a limit already granted is the draft's
  flow-control error (`WT_WEBTRANSPORT_FLOW_CONTROL_ERROR`), because a repeat means the peer
  has lost track of what it granted.
- **A stream count above `2^60`** is the same error: the stream ID space it describes does
  not exist.
- **An omitted initial setting is zero**, not unlimited. A session enabled through one
  setting starts the others at zero, which is what the absence means on the wire.

Asking the allowance first is how a caller never sees the refusal;
`wt_session_flow_record_data` refuses with `WT_ERR_LIMIT` and the peer-facing flow-control
code so that a caller propagating the error closes the session correctly.

## Close and drain

```c
uint8_t out[64]; size_t n = 0;
wt_session_write_drain(session, out, sizeof(out), &n);
wt_session_write_close(session, 0, "bye", out, sizeof(out), &n);
```

Each call moves the state AND writes the capsule into the caller's buffer: there is no way
to send the bytes without the state or the state without the bytes, and both are refused
once the session is closed. Capsules arriving from the peer go the other way:

```c
wt_session_on_capsule(session, bytes, length);   /* drain, close, and the flow-control capsules */
```

A capsule value larger than `max_capsule_bytes` is refused with `WT_ERR_LIMIT` and the
load code, and the session is left as it was.

## Bounds a caller sets

| Field | Default | Refused when |
| --- | --- | --- |
| `max_capsule_bytes` | 16384 | a peer capsule value is larger: `WT_ERR_LIMIT` |
| `max_datagram_bytes` | 65535 | above the QUIC DATAGRAM ceiling at create; a peer payload over it is `WT_ERR_LIMIT` |
| `max_streams` | 64 (`WT_SESSION_STREAM_MAX`) | above the fixed table at create; a peer stream past it is `WT_ERR_LIMIT` |
| `authority` / `path` | -- | longer than the handle's copy: `WT_ERR_LIMIT`, never truncated |

Every one of these is this endpoint's bound. A refusal says which bound was reached and
never blames the peer for it.

## What is not here yet

- **A trust surface.** Chain validation and the trust modes exist in the TLS layer; the
  public wrapper for them is the next part of this phase.
- **Blocking helpers.** The plan allows optional blocking wrappers for the CLI tools and
  simple programs; they arrive with the CLI applications, which are what need them.
- **Streams and datagrams to SEND.** The send side needs the connection that moves the
  bytes, which the CLI phase wires to this API; until then a consumer reports what arrives
  and asks the allowance for what it would send.

## Building against it

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /usr/local     # installs the headers and both libraries
```

`apps/wt-api-sample/main.c` is a complete consumer: it includes the umbrella header, uses
only the functions above, and is built and run by CTest on every platform, so the contract
in this document is checked rather than described.
