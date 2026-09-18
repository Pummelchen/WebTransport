/* Shared by the two halves of test_crypto.c after the split.
 * Composed in the order it has to be read: guard, includes, body defines, shared helpers.
 * The defines come before the helpers because the helpers use them, and `static inline`
 * because a file-static helper cannot cross a translation unit. */
#ifndef TEST_CRYPTO_AEAD_SUPPORT_H
#define TEST_CRYPTO_AEAD_SUPPORT_H

/* The cryptographic primitives, against published vectors.
 *
 * Every value here comes from a document rather than from this code: RFC 4231 for
 * HMAC-SHA256, RFC 5869 for HKDF, NIST's GCM test vectors for AES-128-GCM, RFC
 * 8439 for ChaCha20, and FIPS 197 for the AES block. That matters more here than
 * anywhere else in the library, because a primitive that is wrong in the same way
 * in both directions would round-trip perfectly and produce a protocol that
 * interoperates with nothing -- and the failure would appear as "the peer
 * rejected our packet", which names no cause.
 *
 * The negative cases are the other half: a tag that does not verify must not be
 * reported as success, and a constant-time comparison must return zero for every
 * single-bit difference rather than for the first one it notices.
 */

#include "wt_test.h"

#include "webtransport/crypto/crypto.h"


static inline size_t unhex(const char *hex, uint8_t *out, size_t capacity) {
  size_t length = strlen(hex);
  size_t i;
  if (length % 2U != 0U || length / 2U > capacity) return 0U;
  for (i = 0U; i < length / 2U; i++) {
    unsigned int byte = 0U;
    size_t j;
    for (j = 0U; j < 2U; j++) {
      char c = hex[2U * i + j];
      unsigned int nibble;
      if (c >= '0' && c <= '9') {
        nibble = (unsigned int)(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        nibble = (unsigned int)(c - 'a') + 10U;
      } else if (c >= 'A' && c <= 'F') {
        nibble = (unsigned int)(c - 'A') + 10U;
      } else {
        return 0U;
      }
      byte = (byte << 4) | nibble;
    }
    out[i] = (uint8_t)byte;
  }
  return length / 2U;
}


#endif
