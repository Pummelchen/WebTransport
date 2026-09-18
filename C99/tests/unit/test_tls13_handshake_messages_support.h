/* Shared by the two halves of test_tls13_handshake.c.
 * Static FUNCTIONS become `static inline` so a unit that does not call one is not
 * warned about it; static data and the fake types stay as they are, one copy per
 * translation unit. A file-static helper cannot cross a translation unit, which is
 * why this header exists. */
#ifndef TEST_TLS13_HANDSHAKE_MESSAGES_SUPPORT_H
#define TEST_TLS13_HANDSHAKE_MESSAGES_SUPPORT_H

#include "rfc8448_vectors.h"
#include "webtransport/tls/extension.h"
#include "webtransport/tls/handshake.h"
#include "wt_test.h"
static const uint16_t WT_TEST_CIPHER_SUITES[] = {WT_TLS_CIPHER_AES_128_GCM_SHA256};
static const uint16_t WT_TEST_GROUPS[] = {WT_TLS_GROUP_X25519, WT_TLS_GROUP_SECP256R1};
static const uint16_t WT_TEST_SIGNATURES[] = {WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                                              WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                                              WT_TLS_SIGNATURE_ED25519};
static const char *const WT_TEST_ALPN[] = {"h3"};
static const uint8_t WT_TEST_KEY_SHARE_KEY[32] = {
    0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe,
    0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c};
static const uint8_t WT_TEST_TRANSPORT_PARAMETERS[] = {0x01, 0x02, 0x03, 0x04};

#endif
