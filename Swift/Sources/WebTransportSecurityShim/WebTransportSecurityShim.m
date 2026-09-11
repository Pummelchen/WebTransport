//
//  WebTransportSecurityShim.m
//  WebTransport
//
//  See WebTransportSecurityShim.h for why this file exists.
//

#import "include/WebTransportSecurityShim.h"

#import <Foundation/Foundation.h>

#include <string.h>

const int32_t WTSecPKCS12ImportExceptionStatus = 0x57545858; /* 'WTXX' */

int32_t WTSecPKCS12ImportCatchingExceptions(
    CFDataRef data,
    CFDictionaryRef options,
    CFArrayRef *outItems,
    OSStatus *outStatus,
    const char **outExceptionName,
    const char **outExceptionReason
) {
    if (outExceptionName != NULL) {
        *outExceptionName = NULL;
    }
    if (outExceptionReason != NULL) {
        *outExceptionReason = NULL;
    }
    if (outItems == NULL) {
        if (outStatus != NULL) {
            *outStatus = errSecParam;
        }
        return 0;
    }
    *outItems = NULL;

    @try {
        OSStatus status = SecPKCS12Import(data, options, outItems);
        if (outStatus != NULL) {
            *outStatus = status;
        }
        return 0;
    } @catch (NSException *exception) {
        // The call never returned a status, so report the sentinel and copies of
        // the exception text. The message is copied because the NSException cannot
        // outlive this frame, and Swift needs C strings it can read after the
        // boundary is crossed.
        *outItems = NULL;
        if (outStatus != NULL) {
            *outStatus = WTSecPKCS12ImportExceptionStatus;
        }

        // Thread-local so two threads importing concurrently cannot overwrite each
        // other's message; the contract is documented as "valid until the next call
        // on the same thread".
        static _Thread_local char nameBuffer[128];
        static _Thread_local char reasonBuffer[512];
        const char *name = [[exception name] UTF8String];
        const char *reason = [[exception reason] UTF8String];
        strlcpy(nameBuffer, name != NULL ? name : "NSException", sizeof(nameBuffer));
        strlcpy(reasonBuffer, reason != NULL ? reason : "", sizeof(reasonBuffer));

        if (outExceptionName != NULL) {
            *outExceptionName = nameBuffer;
        }
        if (outExceptionReason != NULL) {
            *outExceptionReason = reasonBuffer;
        }
        return 1;
    }
}
