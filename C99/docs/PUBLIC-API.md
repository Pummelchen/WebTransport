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
| `api/endpoint.h` | Which side this program is, where it is reached, and how the peer's certificate is judged. |
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

## Endpoints and trust

An endpoint says which side this program is, where it is reached, and how the peer's
certificate is judged. A session is then built from it, so the authority a request carries
comes from one place:

```c
wt_endpoint_config_t endpoint = wt_endpoint_config_default();
endpoint.role = WT_ENDPOINT_ROLE_CLIENT;      /* there is no default role */
endpoint.host = "example.com";               /* also the name the certificate must match */
endpoint.port = 443;
endpoint.path = "/chat";                     /* defaults to "/" */
endpoint.trust.mode = WT_TLS_TRUST_SYSTEM;   /* or STORE, PINNED_CERTIFICATE, LOCAL_DEVELOPMENT */
if (wt_endpoint_config_check(&endpoint) != WT_OK) { /* a misconfiguration, before any packet */ }

wt_session_config_t session_config;
wt_endpoint_session_config(&endpoint, 4U, &session_config);   /* CONNECT stream 4 */
```

`host` is the name the peer's certificate is validated against (RFC 6125, through the TLS
layer) unless the policy names its own `host_name`. `authority` defaults to `host`.

| Trust mode | What it does |
| --- | --- |
| `WT_TLS_TRUST_SYSTEM` | The platform's trust store. `WT_ERR_UNSUPPORTED` where there is none. |
| `WT_TLS_TRUST_STORE` | A PEM bundle the caller supplies. |
| `WT_TLS_TRUST_PINNED_CERTIFICATE` | SHA-256 pins of acceptable leaves; at least one, at most `WT_TLS_PINNED_MAX`. |
| `WT_TLS_TRUST_LOCAL_DEVELOPMENT` | The self-signed bypass, **tied to a loopback name**. |

The last one is the one worth reading twice. The bypass is refused for any host name that is
not `localhost`, `127.0.0.1` or `::1`, and the check is the trust layer's own function
(`wt_tls_trust_host_is_loopback`) called from both the configuration check here and the
handshake, so the two cannot drift apart. A caller that reaches for the development policy
against a real endpoint gets `WT_ERR_TRUST` from `wt_endpoint_config_check` -- before a
packet is sent, rather than after a connection that was authenticated by nothing.

A **server** must leave the trust policy unset: this draft has no client authentication, so a
server has no peer certificate to judge, and accepting a policy would be a promise the
library cannot keep. A client must name a port and a trust mode; a server may leave the port
to the system (0) and often will, since binding an ephemeral port is what a test does.

`wt_endpoint_config_check` reports `WT_ERR_INVALID_ARGUMENT` for a missing or impossible
field, `WT_ERR_TRUST` for a mode used outside what it allows, and `WT_ERR_LIMIT` for a path
or authority longer than the session handle copies. It never resolves a name or touches the
network.

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

Each call moves the state AND writes the capsule into the caller's buffer *as the bytes that
go on the CONNECT stream* — the capsule inside the HTTP/3 `DATA` frame RFC 9114 section 4.4
requires there — so there is no way to send the bytes without the state, the state without the
bytes, or the bytes without the framing. A capsule written raw is not a capsule: its type is the
header of an unknown frame type, which a peer ignores in silence. Both calls are refused once
the session is closed. Capsules arriving from the peer go the other way, and the argument is a
capsule — the payload of a `DATA` frame — not the stream's raw bytes:

```c
wt_session_on_capsule(session, bytes, length);   /* drain, close, and the flow-control capsules */
```

A capsule value larger than `max_capsule_bytes` is refused with `WT_ERR_LIMIT` and the
load code, and the session is left as it was. A buffer too small for the frame is refused the
same way rather than truncated.

## Bounds a caller sets

| Field | Default | Refused when |
| --- | --- | --- |
| `max_capsule_bytes` | 16384 | a peer capsule value is larger: `WT_ERR_LIMIT` |
| `max_datagram_bytes` | 65535 | above the QUIC DATAGRAM ceiling at create; a peer payload over it is `WT_ERR_LIMIT` |
| `max_streams` | 64 (`WT_SESSION_STREAM_MAX`) | above the fixed table at create; a peer stream past it is `WT_ERR_LIMIT` |
| `authority` / `path` | -- | longer than the handle's copy: `WT_ERR_LIMIT`, never truncated |

Every one of these is this endpoint's bound. A refusal says which bound was reached and
never blames the peer for it.

## Threading

**There is no lock, no atomic and no thread-local storage anywhere in this library**, and that is a contract
rather than an omission: the table below is what a caller may rely on, and it is written from an inventory of
every piece of shared state rather than from intent. An adversarial audit produced that inventory by walking the
tree for statics, globals and lazily-initialised tables; the ones it found are named here so that a caller does
not have to guess.

| What | Safe? |
| --- | --- |
| One handle (`wt_session_t`, `wt_runtime_session_t`, `wt_udp_socket_t`, `wt_buf_t`, `wt_cli_*`) used from two threads | **No pair of calls is safe.** Every entry point is a read-modify-write on a plain struct -- `wt_session_create`/`destroy`, `established`, `on_capsule`, `on_stream_*`, `on_datagram`, `set_callbacks`, `flow_*`, `write_drain`/`write_close`, `wt_udp_*`, `wt_buf_*` -- and the accessors race with any writer on the same handle (`wt_session_state`, `last_error`, `stream_count`, `flow_snapshot`, ...). One thread per handle at a time |
| Distinct handles on POSIX | Safe. The library has no process-wide mutable state, `malloc`, OpenSSL's RAND and `clock_gettime` are thread-safe, and a handle created with a caller's allocator inherits that allocator's thread-safety |
| Distinct handles on Windows | **Not safe**, because of process-wide state in the platform layer: the Winsock reference count and the latched `WSARecvMsg` provider state in `src/runtime/udp_platform.h` are written by every open and every receive, and `src/core/time.c` caches the performance-counter frequency on first use. A caller that wants concurrent sessions on Windows must serialise the socket layer or use one thread |
| Callbacks | Run synchronously on the caller's thread, inside the call the caller made. A callback must NOT call back into the session -- including `wt_session_destroy` and `wt_session_set_callbacks`: the library settles its own state before a callback runs and writes nothing after it, but the driver that invoked the feed function still owns the handle when the callback returns. Record the decision and act on it after the driver returns. See `webtransport/api/events.h` |
| `wt_udp_socket_t.fd` | Public on purpose, so a caller can put it in its own poll set. Its concurrent use is the caller's own synchronisation |
| Diagnostic logging | Ungated writes to the file named by `WT_HTTP3_*_LOG`-style variables, from whichever thread calls the library. Concurrent logging interleaves; `getenv` concurrent with `setenv` is undefined |

Nothing else in the library is shared: a handle is the unit of both ownership and synchronisation.

## What is not here yet

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
