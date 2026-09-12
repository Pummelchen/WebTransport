/* WebTransport C99: library identity.
 *
 * The version is part of the ABI contract: wt_version_string() returns a static
 * string that never needs freeing, and wt_abi_version() returns the integer that
 * a caller compares against the WT_ABI_VERSION it was compiled with. The two
 * exist separately because a bug-fix release changes the string and not the
 * integer, and a caller checking the integer is checking the thing that can
 * actually break it.
 */

#ifndef WEBTRANSPORT_VERSION_H
#define WEBTRANSPORT_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#define WT_VERSION_MAJOR 0
#define WT_VERSION_MINOR 1
#define WT_VERSION_PATCH 0

/* Incremented only when a public structure's layout, a function's signature, or
 * a documented constant's value changes in a way that a caller compiled against
 * an earlier header would get wrong. */
#define WT_ABI_VERSION 1

/* "0.1.0". Static storage; never freed. */
const char *wt_version_string(void);

/* WT_ABI_VERSION at build time. */
int wt_abi_version(void);

/* The protocol draft this implementation targets, as a string for a User-Agent
 * or a diagnostic -- "draft-ietf-webtrans-http3-16". Static storage. */
const char *wt_protocol_draft(void);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_VERSION_H */
