//
//  WebTransportSecurityShim.h
//  WebTransport
//
//  A narrow exception boundary around Security.framework entry points that can
//  terminate the process instead of reporting failure.
//
//  `SecPKCS12Import` raises an Objective-C `NSException` when the identity it is
//  asked to build cannot be constructed — for example when a certificate carries
//  explicit elliptic-curve parameters rather than a named curve. Security.framework
//  dereferences a NULL `SecKeyRef` while building trust chains, and the resulting
//  `NSInvalidArgumentException` unwinds the stack and aborts the process.
//
//  Swift cannot catch an Objective-C exception, so the only place this failure can
//  be turned into an ordinary error is an Objective-C frame. This shim provides
//  exactly one such frame and reports what happened as data.
//

#ifndef WEBTRANSPORT_SECURITY_SHIM_H
#define WEBTRANSPORT_SECURITY_SHIM_H

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Status reported through `outStatus` when an Objective-C exception was raised.
/// `OSStatus` has no value reserved for "an exception was thrown", and the real
/// `OSStatus` is unavailable because the call never returned, so a distinct
/// sentinel is reported instead.
///
/// Callers must test the `raisedException` out-parameter rather than comparing
/// `outStatus` against `errSecSuccess` alone; on the exception path the status is
/// meaningless.
///
/// The sentinel is the four-character code `'WTXX'`, chosen to be recognisable in
/// a log and distinct from the four-character codes Security.framework returns.
extern const int32_t WTSecPKCS12ImportExceptionStatus;

/// Calls `SecPKCS12Import`, converting an Objective-C exception into a status
/// code and copies of the exception text instead of letting it abort the process.
///
/// Results are returned through out-parameters rather than a C struct because
/// Swift, with strict memory safety enabled, treats an imported C struct as an
/// unsafe type and would require an `unsafe` marker on every field access; out-
/// parameters confine that to the call itself.
///
/// On success (including ordinary `OSStatus` failures) the behaviour matches
/// `SecPKCS12Import`: `*outItems` follows the Create Rule and the caller owns it.
/// On the exception path `*outItems` is set to NULL.
///
/// `outExceptionName` and `outExceptionReason` are optional (NULL may be passed);
/// when supplied they receive the exception text when one was raised, or NULL
/// otherwise. The strings are owned by the shim and remain valid until the next
/// call on the same thread, so a caller must copy anything it needs to retain.
///
/// `outItems` carries `CF_RETURNS_RETAINED` so the imported Swift signature takes
/// a plain `CFArray?` rather than an `Unmanaged<CFArray>?`.
///
/// - Returns: 1 when an Objective-C exception was raised and caught, 0 otherwise.
int32_t WTSecPKCS12ImportCatchingExceptions(
    CFDataRef _Nonnull data,
    CFDictionaryRef _Nonnull options,
    CFArrayRef _Nullable * _Nonnull CF_RETURNS_RETAINED outItems,
    OSStatus * _Nullable outStatus,
    const char * _Nullable * _Nullable outExceptionName,
    const char * _Nullable * _Nullable outExceptionReason);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_SECURITY_SHIM_H */
