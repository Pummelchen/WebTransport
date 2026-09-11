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
    const char **outExceptionName
) {
    if (outExceptionName != NULL) {
        *outExceptionName = NULL;
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
        // The call never returned a status, so report the sentinel instead. The name
        // is copied because the NSException cannot outlive this frame and Swift needs
        // a C string it can read after the boundary is crossed. The reason is not:
        // it is a fixed string from Security.framework that carries nothing a caller
        // can act on, and the caller states the actionable cause itself.
        *outItems = NULL;
        if (outStatus != NULL) {
            *outStatus = WTSecPKCS12ImportExceptionStatus;
        }

        // Thread-local so two threads importing concurrently cannot overwrite each
        // other's name; the header documents the resulting contract, which is that
        // the pointer stays valid only until the next call on the same thread.
        static _Thread_local char nameBuffer[128];
        const char *name = [[exception name] UTF8String];
        strlcpy(nameBuffer, name != NULL ? name : "NSException", sizeof(nameBuffer));
        if (outExceptionName != NULL) {
            *outExceptionName = nameBuffer;
        }
        return 1;
    }
}
