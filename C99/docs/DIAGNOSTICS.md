# Diagnostics: the environment-gated dumps

This tree answers questions about itself with counters (`.json` reports, the compliance matrix, the
interop runners). Counters say *that* something happened; five dumps say *what was on the wire*, and
they exist because four separate interop investigations could not be closed with counters alone. Each
one is off unless an environment variable names a file, and each one is **never** on in production.

They were added under pressure during those investigations, one at a time, which is why this page
exists: the next person should not have to rediscover them, and the decision to have them in the
library should be a documented one rather than an accumulation.

| Variable | Written by | Records | The question it answers |
| --- | --- | --- | --- |
| `WT_QUIC_PACKET_LOG` | `src/quic/connection.c` | one line per packet **sent**: space, header type bits, first byte, length, packet number, and the whole packet in hex (up to 1300 bytes) | "did this endpoint send anything, and was it the packet I think it built?" |
| `WT_TLS_SECRET_LOG` | `src/tls/session.c` (at derivation) and `apps/support/session_loop.c` (the client's keylog line) | the handshake traffic secrets: `# at-derivation client=... server=...` from the library, and `CLIENT_HANDSHAKE_TRAFFIC_SECRET ...` in NSS keylog form from the client tool | "are the two ends deriving the SAME secret, or is one of them wrong?" |
| `WT_TLS_TRANSCRIPT_LOG` | `src/tls/session.c` (both ClientHello entry points) | the ClientHello bytes this client **hashed** into the transcript | "did the transcript hash the bytes that went out on the wire?" |
| `WT_HTTP3_SECTION_LOG` | `apps/support/session_loop.c` | the request's field section in hex, and every HTTP/3 frame payload on the request stream (`stream= type= length= last= bytes=`) | "what did the peer actually send after the response, and what did this endpoint parse it as?" |
| `WT_HTTP3_STREAM_LOG` | `src/http3/driver.c` | every STREAM frame the driver is asked to route: `stream= offset= has_length= length= fin= bytes=` | "was that stream routed as a WebTransport data stream or parsed as HTTP/3 frames?" |

Usage is the same for all five:

```sh
WT_HTTP3_STREAM_LOG=/tmp/streams.txt \
WT_QUIC_PACKET_LOG=/tmp/packets.txt \
  the-tool --connect ... --json
```

A file is opened in append mode per record, so a run can be added to an existing file; to compare two
runs, **remove the file first**, because every one of these appends.

## What each one found

These are the defects the dumps closed, in the order they were added, because that is the argument for
keeping them:

* `WT_QUIC_PACKET_LOG` — the client's Handshake packets were addressed to a connection ID the peer did
  not know, so the peer dropped them **before** consulting any key. The packet log said which ID went
  out; the peer's own "unknown connection" line said what it expected. (`WT-135`/`WT-138`.)
* `WT_TLS_SECRET_LOG` and `WT_TLS_TRANSCRIPT_LOG` — a peer could not open this client's Finished while
  this client opened the peer's. Comparing the two ends' secrets byte for byte, and the hashed
  ClientHello against the one decrypted from its own Initial packet, is what separated "the derivation
  is wrong" from "the bytes hashed are not the bytes sent". (`WT-135`.)
* `WT_HTTP3_SECTION_LOG` — a third-party peer's CONNECT decoded as `:protocol: localhostort`. The dump
  gave the 32 bytes, an independent decoder (pylsqpack) gave the five pseudo-headers, and the
  comparison showed a field's bytes being overwritten by the field after it. (`WT-154`.)
* `WT_HTTP3_STREAM_LOG` — the same peer sent a WebTransport prefix in one STREAM frame and its message
  in the next; the dump showed the two frames, which named a driver that classified the prefix and then
  forgot it. (`WT-156`.)

## The cost, and why it is acceptable

* **Off means off, and nearly free**: one `getenv` per call on the paths that already exist — a packet
  send, a secret derivation, a frame payload — and one `fopen`/`fclose` pair per record when a variable
  is set. Nothing is formatted, allocated or opened when the variables are unset.
* **These write secrets.** `WT_TLS_SECRET_LOG` writes traffic secrets in the clear, and the packet log
  writes whole packets; both are only ever set by the interop and investigation workflows, never by the
  tools themselves and never in CI.
* **The library reads the environment.** That is a deliberate exception to "the library never writes to
  a stream, a file or stderr" (`include/webtransport/log.h`): the alternative was to thread a
  diagnostics sink through the QUIC, TLS and HTTP/3 layers, and the counter-argument won — a dump that
  needs a caller to configure it does not exist at the moment it is needed.

## What is deliberately NOT here

A production tracing surface. These are file dumps for a person reading them after the fact, they have
no levels, no timestamps and no structure beyond `key=value`, and the library's own logging surface
(`wt_logger_t`) is a separate, caller-owned thing. A query language over frames is a debugger's job,
not a library's.
