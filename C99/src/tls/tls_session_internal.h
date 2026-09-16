/* Declarations shared across the TLS 1.3 session's translation units.
 *
 * The handshake was one file with a client half and a server half. They are now
 * `session_client.c` and `session_server.c`, and the one thing they share is the ciphersuite both
 * offer: it must be the same value on both sides or the handshake has no schedule to run. It lived
 * in the file as a `#define`; it lives here so the two halves cannot drift.
 *
 * Nothing here is part of the installed API (see webtransport/tls/session.h). */

#ifndef WT_TLS_SESSION_INTERNAL_H
#define WT_TLS_SESSION_INTERNAL_H

#include "webtransport/tls/session.h"

#include "webtransport/tls/extension.h"

/* The ciphersuite this implementation offers, which is the only one it has a schedule for
 * (RFC 8446 section 9.1 makes it mandatory). */
#define WT_TLS_CIPHER_SUITE WT_TLS_CIPHER_AES_128_GCM_SHA256

#endif /* WT_TLS_SESSION_INTERNAL_H */
