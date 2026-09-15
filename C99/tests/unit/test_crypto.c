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

/* Hex to bytes, for the vectors below. A local helper rather than a large
 * transcription: the strings are copied from the documents and this is the only
 * thing that has to be right about them. */
static size_t unhex(const char *hex, uint8_t *out, size_t capacity) {
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

static void test_sha256(void) {
  uint8_t out[WT_SHA256_LEN];
  uint8_t want[WT_SHA256_LEN];

  /* NIST's SHA-256 of "abc". */
  WT_EXPECT_OK("sha256 of abc", wt_sha256("abc", 3U, out));
  unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* The empty string, which is the hash the TLS 1.3 key schedule takes
   * "derived" from. */
  WT_EXPECT_OK("sha256 of nothing", wt_sha256("", 0U, out));
  unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* A 56-byte message, which is one byte short of the block boundary and is
   * where a padding implementation first goes wrong. */
  WT_EXPECT_OK("sha256 of 56 bytes",
               wt_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                         56U, out));
  unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* The streaming interface must agree with the one-shot, including for a
   * message written in two pieces across the block boundary. */
  {
    wt_sha256_ctx_t ctx;
    uint8_t one_shot[WT_SHA256_LEN];
    WT_EXPECT_OK("a context starts", wt_sha256_init(&ctx));
    WT_EXPECT_OK("and takes a first piece",
                 wt_sha256_update(&ctx, "abcdbcdecdefdefgefghfghighijhijk", 32U));
    WT_EXPECT_OK("and a second",
                 wt_sha256_update(&ctx,
                                  "ijkljklmklmnlmnomnopnopq", 24U));
    WT_EXPECT_OK("and finishes", wt_sha256_final(&ctx, out));
    WT_EXPECT_OK("the one-shot agrees",
                 wt_sha256("abcdbcdecdefdefgefghfghighijhijk"
                           "ijkljklmklmnlmnomnopnopq",
                           56U, one_shot));
    WT_EXPECT_BYTES("with the same digest", one_shot, out, WT_SHA256_LEN);
  }

  /* The snapshot: the hash of the message so far, leaving the context usable.
   * This is what a handshake transcript reads at each point where the key schedule
   * needs a hash, so "the context survives it" is the property under test. */
  {
    wt_sha256_ctx_t ctx;
    uint8_t so_far[WT_SHA256_LEN];
    uint8_t rest[WT_SHA256_LEN];
    uint8_t want_abc[WT_SHA256_LEN];
    uint8_t want_abcdef[WT_SHA256_LEN];
    unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          want_abc, sizeof(want_abc));
    unhex("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721",
          want_abcdef, sizeof(want_abcdef));
    WT_EXPECT_OK("a snapshot context starts", wt_sha256_init(&ctx));
    WT_EXPECT_OK("and takes the first half",
                 wt_sha256_update(&ctx, "abc", 3U));
    WT_EXPECT_OK("the hash so far", wt_sha256_snapshot(&ctx, so_far));
    WT_EXPECT_BYTES("is the hash of the first half", want_abc, so_far,
                    WT_SHA256_LEN);
    /* Reading it twice gives the same answer, and the context still absorbs. */
    WT_EXPECT_OK("read again", wt_sha256_snapshot(&ctx, so_far));
    WT_EXPECT_BYTES("to the same value", want_abc, so_far, WT_SHA256_LEN);
    WT_EXPECT_OK("the context takes the second half",
                 wt_sha256_update(&ctx, "def", 3U));
    WT_EXPECT_OK("and finalises", wt_sha256_final(&ctx, rest));
    WT_EXPECT_BYTES("to the whole message's hash", want_abcdef, rest,
                    WT_SHA256_LEN);
    WT_EXPECT_STATUS("snapshotting into NULL is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_sha256_snapshot(&ctx, NULL));
    /* Finalising ended the context, so a snapshot of it is a state error rather
     * than a hash of the last block. This is also the state a caller is left in
     * after final, which is why the check belongs here rather than on a context
     * that was never initialised: what the library can recognise is a context it
     * owns and has finished with, not whatever a caller's stack happened to hold. */
    WT_EXPECT_STATUS("a snapshot after final is a state error", WT_ERR_STATE,
                     wt_sha256_snapshot(&ctx, so_far));
  }

  /* The refusals. */
  WT_EXPECT_STATUS("a NULL context is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_sha256_init(NULL));
  WT_EXPECT_STATUS("snapshotting a NULL context is refused",
                   WT_ERR_INVALID_ARGUMENT, wt_sha256_snapshot(NULL, out));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_sha256("abc", 3U, NULL));
  WT_EXPECT_STATUS("NULL data with a length is refused",
                   WT_ERR_INVALID_ARGUMENT, wt_sha256(NULL, 3U, out));
  {
    /* A context the library has never touched. Both cases are written out rather
     * than left to the stack: the guarantee being checked is that a context which
     * was zeroed (a static or value-initialised one) or which holds something else
     * entirely is refused with WT_ERR_STATE rather than dereferenced, and an
     * uninitialised stack local would make the test depend on what the previous
     * frame left there instead. */
    wt_sha256_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    WT_EXPECT_STATUS("updating a zeroed context is refused", WT_ERR_STATE,
                     wt_sha256_update(&ctx, "a", 1U));
    WT_EXPECT_STATUS("finalising a zeroed context is refused", WT_ERR_STATE,
                     wt_sha256_final(&ctx, out));
    WT_EXPECT_STATUS("snapshotting a zeroed context is refused", WT_ERR_STATE,
                     wt_sha256_snapshot(&ctx, out));
    memset(&ctx, 0xAB, sizeof(ctx));
    WT_EXPECT_STATUS("updating a context that holds something else is refused",
                     WT_ERR_STATE, wt_sha256_update(&ctx, "a", 1U));
    WT_EXPECT_STATUS("finalising it is refused", WT_ERR_STATE,
                     wt_sha256_final(&ctx, out));
  }
}

static void test_hmac(void) {
  uint8_t out[WT_SHA256_LEN];
  uint8_t want[WT_SHA256_LEN];
  uint8_t key[131];

  /* RFC 4231 test case 1: a 20-byte key of 0x0b and "Hi There". */
  memset(key, 0x0b, 20U);
  WT_EXPECT_OK("RFC 4231 case 1", wt_hmac_sha256(key, 20U,
                                                (const uint8_t *)"Hi There", 8U,
                                                out));
  unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* Case 2: a short key, "Jefe". */
  WT_EXPECT_OK("RFC 4231 case 2",
               wt_hmac_sha256((const uint8_t *)"Jefe", 4U,
                              (const uint8_t *)"what do ya want for nothing?", 28U,
                              out));
  unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* Case 6: a 131-byte key, which is longer than the block size and so must be
   * hashed first -- the case a naive implementation gets wrong. The message is
   * the RFC's, and its length is checked against the length the RFC states so
   * that a typo here cannot quietly make the vector mean something else. */
  {
    static const char message[] =
        "Test Using Larger Than Block-Size Key - Hash Key First";
    memset(key, 0xaa, 131U);
    WT_EXPECT_U64("RFC 4231 case 6's message length", 54U,
                  (uint64_t)(sizeof(message) - 1U));
    WT_EXPECT_OK("RFC 4231 case 6",
                 wt_hmac_sha256(key, 131U, (const uint8_t *)message,
                                sizeof(message) - 1U, out));
    unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
          want, sizeof(want));
    WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);
  }

  /* Case 7: a 131-byte key and a 152-byte message. */
  {
    static const char message[] =
        "This is a test using a larger than block-size key and a larger than "
        "block-size data. The key needs to be hashed before being used by the "
        "HMAC algorithm.";
    memset(key, 0xaa, 131U);
    WT_EXPECT_U64("RFC 4231 case 7's message length", 152U,
                  (uint64_t)(sizeof(message) - 1U));
    WT_EXPECT_OK("RFC 4231 case 7",
                 wt_hmac_sha256(key, 131U, (const uint8_t *)message,
                                sizeof(message) - 1U, out));
    unhex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
          want, sizeof(want));
    WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);
  }
}

static void test_hkdf(void) {
  uint8_t prk[WT_SHA256_LEN];
  uint8_t okm[82];
  uint8_t want[82];

  /* RFC 5869 test case 1: a 22-byte IKM of 0x0b and a 13-byte salt of
   * 0x000102...0c. */
  {
    static const uint8_t ikm[22] = {0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU};
    uint8_t salt[13];
    uint8_t info[10];
    size_t i;
    for (i = 0U; i < sizeof(salt); i++) salt[i] = (uint8_t)i;
    for (i = 0U; i < sizeof(info); i++) info[i] = (uint8_t)(0xf0U + i);

    WT_EXPECT_OK("RFC 5869 case 1 extracts",
                 wt_hkdf_extract_sha256(salt, sizeof(salt), ikm, sizeof(ikm),
                                        prk));
    unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
          want, 32U);
    WT_EXPECT_BYTES("and the PRK is the published value", want, prk,
                    WT_SHA256_LEN);

    WT_EXPECT_OK("and expands", wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, info,
                                                      sizeof(info), okm, 42U));
    unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865",
          want, 42U);
    WT_EXPECT_BYTES("and the OKM is the published value", want, okm, 42U);
  }

  /* Case 3: no salt and no info, which is the case the TLS 1.3 schedule uses for
   * the early secret and where "no salt" must mean a zero salt of hash length. */
  {
    static const uint8_t ikm[22] = {0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU};
    WT_EXPECT_OK("RFC 5869 case 3 extracts with no salt",
                 wt_hkdf_extract_sha256(NULL, 0U, ikm, sizeof(ikm), prk));
    unhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
          want, 32U);
    WT_EXPECT_BYTES("and the PRK is the published value", want, prk,
                    WT_SHA256_LEN);
    WT_EXPECT_OK("and expands with no info",
                 wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, NULL, 0U, okm, 42U));
    unhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
          "9d201395faa4b61a96c8",
          want, 42U);
    WT_EXPECT_BYTES("and the OKM is the published value", want, okm, 42U);
  }

  /* The output bound: 255 blocks of 32 bytes is the most RFC 5869 allows, and a
   * longer request must be refused rather than wrap the counter. */
  {
    uint8_t large[255U * 32U];
    WT_EXPECT_OK("the largest allowed output",
                 wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, NULL, 0U, large,
                                       sizeof(large)));
    WT_EXPECT_STATUS("one byte more is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, NULL, 0U,
                                           large, sizeof(large) + 1U));
    WT_EXPECT_STATUS("a NULL PRK is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_sha256(NULL, 0U, NULL, 0U, large, 32U));
    WT_EXPECT_OK("a zero-length expansion is allowed",
                 wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, NULL, 0U, large, 0U));
  }
}

static void test_hkdf_expand_label(void) {
  uint8_t out[32];
  uint8_t want[32];
  uint8_t secret[32];

  /* RFC 8446 section 7.1's structure, checked through RFC 9001 A.5's labels:
   * HKDF-Expand-Label(secret, "quic key", "", 32) from the ChaCha20 secret. */
  {
    static const uint8_t chacha_secret[32] = {
        0x9aU, 0xc3U, 0x12U, 0xa7U, 0xf8U, 0x77U, 0x46U, 0x8eU,
        0xbeU, 0x69U, 0x42U, 0x27U, 0x48U, 0xadU, 0x00U, 0xa1U,
        0x54U, 0x43U, 0xf1U, 0x82U, 0x03U, 0xa0U, 0x7dU, 0x60U,
        0x60U, 0xf6U, 0x88U, 0xf3U, 0x0fU, 0x21U, 0x63U, 0x2bU};
    WT_EXPECT_OK("quic key from the ChaCha20 secret",
                 wt_hkdf_expand_label_sha256(chacha_secret, sizeof(chacha_secret),
                                             "quic key", NULL, 0U, out, 32U));
    unhex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
          want, 32U);
    WT_EXPECT_BYTES("is the RFC's value", want, out, 32U);

    WT_EXPECT_OK("quic iv from the same secret",
                 wt_hkdf_expand_label_sha256(chacha_secret, sizeof(chacha_secret),
                                             "quic iv", NULL, 0U, out, 12U));
    unhex("e0459b3474bdd0e44a41c144", want, 12U);
    WT_EXPECT_BYTES("is the RFC's value", want, out, 12U);
  }

  /* The context is length-prefixed and is part of the expansion: a derivation
   * with a context must differ from the same derivation without one, or the
   * length prefix is being dropped. */
  {
    uint8_t with_context[32];
    uint8_t without_context[32];
    memset(secret, 0x42, sizeof(secret));
    WT_EXPECT_OK("with a context",
                 wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic key",
                                             (const uint8_t *)"abc", 3U,
                                             with_context, 32U));
    WT_EXPECT_OK("without one",
                 wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic key",
                                             NULL, 0U, without_context, 32U));
    WT_EXPECT_INT("the two differ", 0,
                  memcmp(with_context, without_context, 32U) == 0 ? 1 : 0);
  }

  /* The label is prefixed with "tls13 ": a derivation under a label and under a
   * label with that prefix already in it must differ, which they would not if the
   * prefix were being dropped. */
  {
    uint8_t a[32];
    uint8_t b[32];
    memset(secret, 0x11, sizeof(secret));
    WT_EXPECT_OK("label quic key",
                 wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic key",
                                             NULL, 0U, a, 32U));
    WT_EXPECT_OK("label tls13 quic key",
                 wt_hkdf_expand_label_sha256(secret, sizeof(secret),
                                             "tls13 quic key", NULL, 0U, b,
                                             32U));
    WT_EXPECT_INT("the two differ", 0, memcmp(a, b, 32U) == 0 ? 1 : 0);
  }

  /* The output length is part of the expansion, not a truncation: a 16-byte
   * expansion of a secret is not the first 16 bytes of its 32-byte expansion.
   * This is the defect RFC 9001's header protection key length turned on. */
  {
    uint8_t short_out[16];
    uint8_t long_out[32];
    memset(secret, 0x77, sizeof(secret));
    WT_EXPECT_OK("a 16-byte expansion",
                 wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic hp",
                                             NULL, 0U, short_out, 16U));
    WT_EXPECT_OK("a 32-byte expansion",
                 wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic hp",
                                             NULL, 0U, long_out, 32U));
    WT_EXPECT_INT("which is not its prefix", 0,
                  memcmp(short_out, long_out, 16U) == 0 ? 1 : 0);
  }

  /* Refusals: a label too long for its own length prefix, a context above 255,
   * and NULL arguments. */
  {
    char long_label[260];
    memset(long_label, 'a', sizeof(long_label) - 1U);
    long_label[sizeof(long_label) - 1U] = '\0';
    WT_EXPECT_STATUS("a 259-byte label is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(secret, sizeof(secret),
                                                 long_label, NULL, 0U, out,
                                                 32U));
    WT_EXPECT_STATUS("a 256-byte context is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(secret, sizeof(secret),
                                                 "quic key", secret, 256U, out,
                                                 32U));
    WT_EXPECT_STATUS("a NULL secret is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(NULL, 32U, "quic key", NULL, 0U,
                                                 out, 32U));
    WT_EXPECT_STATUS("a NULL label is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(secret, 32U, NULL, NULL, 0U,
                                                 out, 32U));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(secret, 32U, "quic key", NULL,
                                                 0U, NULL, 32U));
    /* A 255-byte context is allowed, and a 249-byte label. */
    {
      uint8_t context[255];
      char label[250];
      memset(context, 0x5aU, sizeof(context));
      memset(label, 'b', 249U);
      label[249] = '\0';
      WT_EXPECT_OK("a 255-byte context is allowed",
                   wt_hkdf_expand_label_sha256(secret, 32U, "quic key", context,
                                               sizeof(context), out, 32U));
      WT_EXPECT_OK("a 249-byte label is allowed",
                   wt_hkdf_expand_label_sha256(secret, 32U, label, NULL, 0U, out,
                                               32U));
    }
  }
}

static void test_aead(void) {
  /* NIST's GCM test case 3: a 16-byte key of zeros, a 12-byte IV of zeros, an
   * empty plaintext, and a 16-byte tag. The simplest possible case, and the one
   * where a wrong tag length or a wrong nonce shows up immediately. */
  {
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t tag[WT_AEAD_TAG_LEN];
    uint8_t want[WT_AEAD_TAG_LEN];
    uint8_t out[1];
    WT_EXPECT_OK("an empty plaintext seals", wt_aead_seal(WT_AEAD_AES_128_GCM,
                                                          key, iv, NULL, 0U,
                                                          NULL, 0U, out, tag));
    unhex("58e2fccefa7e3061367f1d57a4e7455a", want, sizeof(want));
    WT_EXPECT_BYTES("and the tag is the published value", want, tag,
                    WT_AEAD_TAG_LEN);

    /* The same tag opens it, and a tag that is not this one does not. */
    WT_EXPECT_OK("and the same tag opens it",
                 wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, NULL, 0U,
                              tag, out));
    tag[0] ^= 0x01U;
    WT_EXPECT_STATUS("and a one-bit difference does not",
                     WT_ERR_AUTHENTICATION,
                     wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, NULL,
                                  0U, tag, out));
  }

  /* NIST's GCM test case 4: a single 16-byte block of zeros. */
  {
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t plain[16] = {0};
    uint8_t cipher[16];
    uint8_t back[16];
    uint8_t tag[WT_AEAD_TAG_LEN];
    uint8_t want_cipher[16];
    uint8_t want_tag[WT_AEAD_TAG_LEN];
    WT_EXPECT_OK("a block of zeros seals",
                 wt_aead_seal(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, plain,
                              sizeof(plain), cipher, tag));
    unhex("0388dace60b6a392f328c2b971b2fe78", want_cipher, 16U);
    unhex("ab6e47d42cec13bdf53a67b21257bddf", want_tag, sizeof(want_tag));
    WT_EXPECT_BYTES("and the ciphertext is the published value", want_cipher,
                    cipher, 16U);
    WT_EXPECT_BYTES("and so is the tag", want_tag, tag, WT_AEAD_TAG_LEN);
    WT_EXPECT_OK("and it opens",
                 wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, cipher,
                              sizeof(cipher), tag, back));
    WT_EXPECT_BYTES("to the plaintext that was sealed", plain, back,
                    sizeof(back));
  }

  /* NIST's GCM test case 5, with additional authenticated data: this is the case
   * QUIC uses, because the packet header is the AAD. */
  {
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t aad[20];
    /* The vector's plaintext is 60 bytes, not a whole number of blocks, which is
     * the case that catches a finalisation bug. The buffers are sized to the
     * vector so that no byte of them is read uninitialised. */
    uint8_t plain[60];
    uint8_t cipher[60];
    uint8_t tag[WT_AEAD_TAG_LEN];
    uint8_t back[60];
    uint8_t want_cipher[60];
    uint8_t want_tag[WT_AEAD_TAG_LEN];
    size_t i;
    unhex("feffe9928665731c6d6a8f9467308308", key, sizeof(key));
    unhex("cafebabefacedbaddecaf888", iv, sizeof(iv));
    unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, sizeof(aad));
    unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
          "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
          plain, sizeof(plain));
    unhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
          "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
          want_cipher, sizeof(want_cipher));
    unhex("5bc94fbc3221a5db94fae95ae7121a47", want_tag, sizeof(want_tag));
    WT_EXPECT_OK("a plaintext with associated data seals",
                 wt_aead_seal(WT_AEAD_AES_128_GCM, key, iv, aad, sizeof(aad),
                              plain, sizeof(plain), cipher, tag));
    WT_EXPECT_BYTES("and the ciphertext is the published value", want_cipher,
                    cipher, sizeof(cipher));
    WT_EXPECT_BYTES("and so is the tag", want_tag, tag, WT_AEAD_TAG_LEN);

    /* It opens, in place, back to the published plaintext. */
    memcpy(back, cipher, sizeof(back));
    WT_EXPECT_OK("and it opens in place",
                 wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, aad, sizeof(aad),
                              back, sizeof(back), tag, back));
    WT_EXPECT_BYTES("back to the plaintext", plain, back, sizeof(back));

    /* A single flipped bit in the ciphertext must be refused, and the plaintext
     * buffer must hold nothing afterwards: that is the property the API exists
     * for, and a caller that ignored the status would find no bytes to misuse. */
    {
      uint8_t damaged[60];
      size_t nonzero = 0U;
      memcpy(damaged, cipher, sizeof(damaged));
      damaged[7] ^= 0x01U;
      WT_EXPECT_STATUS("a flipped ciphertext bit is refused",
                       WT_ERR_AUTHENTICATION,
                       wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, aad,
                                    sizeof(aad), damaged, sizeof(damaged), tag,
                                    damaged));
      for (i = 0U; i < sizeof(damaged); i++) {
        if (damaged[i] != 0U) nonzero++;
      }
      WT_EXPECT_U64("and the plaintext was cleared", 0U, (uint64_t)nonzero);
    }
    /* A changed AAD is refused too: this is the case a peer would use to move a
     * protected payload between packets, and the tag must not survive it. */
    {
      uint8_t other_aad[20];
      uint8_t out[60];
      memcpy(other_aad, aad, sizeof(other_aad));
      other_aad[0] ^= 0x01U;
      WT_EXPECT_STATUS("a changed AAD is refused", WT_ERR_AUTHENTICATION,
                       wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, other_aad,
                                    sizeof(other_aad), cipher, sizeof(cipher),
                                    tag, out));
    }
    /* A truncated tag is a different tag: the last byte of the AAD's tag is
     * compared, not just the first. */
    {
      uint8_t short_tag[WT_AEAD_TAG_LEN];
      uint8_t out[60];
      memcpy(short_tag, tag, sizeof(short_tag));
      short_tag[WT_AEAD_TAG_LEN - 1U] ^= 0x80U;
      WT_EXPECT_STATUS("a damaged final tag byte is refused",
                       WT_ERR_AUTHENTICATION,
                       wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, aad,
                                    sizeof(aad), cipher, sizeof(cipher),
                                    short_tag, out));
    }
  }

  /* RFC 8439 section 2.8.2: ChaCha20-Poly1305 with AAD. */
  {
    uint8_t key[32];
    uint8_t iv[12];
    uint8_t aad[12];
    uint8_t plain[114];
    uint8_t cipher[114];
    uint8_t back[114];
    uint8_t want_cipher[114];
    uint8_t tag[WT_AEAD_TAG_LEN];
    uint8_t want_tag[WT_AEAD_TAG_LEN];
    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
          key, sizeof(key));
    unhex("070000004041424344454647", iv, sizeof(iv));
    unhex("50515253c0c1c2c3c4c5c6c7", aad, sizeof(aad));
    unhex("4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
          "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
          "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
          "637265656e20776f756c642062652069742e",
          plain, sizeof(plain));
    unhex("1ae10b594f09e26a7e902ecbd0600691", want_tag, sizeof(want_tag));
    unhex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
          "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
          "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
          "3ff4def08e4b7a9de576d26586cec64b6116",
          want_cipher, sizeof(want_cipher));
    WT_EXPECT_OK("the ChaCha20-Poly1305 vector seals",
                 wt_aead_seal(WT_AEAD_CHACHA20_POLY1305, key, iv, aad,
                              sizeof(aad), plain, sizeof(plain), cipher, tag));
    WT_EXPECT_BYTES("with the published tag", want_tag, tag, WT_AEAD_TAG_LEN);
    WT_EXPECT_BYTES("and the published ciphertext", want_cipher, cipher,
                    sizeof(cipher));
    WT_EXPECT_OK("and it opens", wt_aead_open(WT_AEAD_CHACHA20_POLY1305, key, iv,
                                              aad, sizeof(aad), cipher,
                                              sizeof(cipher), tag, back));
    WT_EXPECT_BYTES("back to the published plaintext", plain, back,
                    sizeof(back));
    tag[0] ^= 0x01U;
    WT_EXPECT_STATUS("and a damaged tag is refused", WT_ERR_AUTHENTICATION,
                     wt_aead_open(WT_AEAD_CHACHA20_POLY1305, key, iv, aad,
                                  sizeof(aad), cipher, sizeof(cipher), tag,
                                  back));
  }

  /* The suite's sizes. */
  WT_EXPECT_U64("AES-128-GCM key", 16U,
                (uint64_t)wt_aead_key_len(WT_AEAD_AES_128_GCM));
  WT_EXPECT_U64("ChaCha20 key", 32U,
                (uint64_t)wt_aead_key_len(WT_AEAD_CHACHA20_POLY1305));
  WT_EXPECT_U64("IV length", 12U, (uint64_t)wt_aead_iv_len(WT_AEAD_AES_128_GCM));
  WT_EXPECT_U64("tag length", 16U, (uint64_t)wt_aead_tag_len(WT_AEAD_AES_128_GCM));
  WT_EXPECT_U64("an unknown suite has no key", 0U,
                (uint64_t)wt_aead_key_len((wt_aead_t)99));
  WT_EXPECT_STR("aes-128-gcm is named", "aes-128-gcm",
                wt_aead_name(WT_AEAD_AES_128_GCM));
  WT_EXPECT_STR("chacha20-poly1305 is named", "chacha20-poly1305",
                wt_aead_name(WT_AEAD_CHACHA20_POLY1305));
  WT_EXPECT_STR("an unknown suite", "unknown", wt_aead_name((wt_aead_t)99));

  /* An unsupported suite is refused rather than treated as AES, and the
   * argument checks are the same in both directions. */
  {
    uint8_t key[16] = {0};
    uint8_t tag[WT_AEAD_TAG_LEN] = {0};
    uint8_t out[16] = {0};
    WT_EXPECT_STATUS("an unknown AEAD is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_aead_seal((wt_aead_t)99, key, key, NULL, 0U, out, 1U,
                                  out, tag));
    WT_EXPECT_STATUS("an unknown AEAD is refused when opening",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open((wt_aead_t)99, key, key, NULL, 0U, out, 1U,
                                  tag, out));
    WT_EXPECT_STATUS("a NULL tag is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_aead_seal(WT_AEAD_AES_128_GCM, key, key, NULL, 0U, out,
                                  1U, out, NULL));
    WT_EXPECT_STATUS("a NULL tag is refused when opening",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open(WT_AEAD_AES_128_GCM, key, key, NULL, 0U, out,
                                  1U, NULL, out));
    WT_EXPECT_STATUS("a NULL key is refused when opening",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open(WT_AEAD_AES_128_GCM, NULL, key, NULL, 0U, out,
                                  1U, tag, out));
    WT_EXPECT_STATUS("a NULL IV is refused when opening",
                     WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open(WT_AEAD_AES_128_GCM, key, NULL, NULL, 0U, out,
                                  1U, tag, out));
  }
}

static void test_aes_block_and_chacha(void) {
  /* FIPS 197 appendix C.1: AES-128 of a known block. */
  {
    uint8_t key[16];
    uint8_t in[16];
    uint8_t out[16];
    uint8_t want[16];
    unhex("000102030405060708090a0b0c0d0e0f", key, sizeof(key));
    unhex("00112233445566778899aabbccddeeff", in, sizeof(in));
    unhex("69c4e0d86a7b0430d8cdb78070b4c55a", want, sizeof(want));
    WT_EXPECT_OK("the AES-128 block vector",
                 wt_aes128_ecb_encrypt_block(key, in, out));
    WT_EXPECT_BYTES("and it is the published value", want, out, 16U);
    /* The block is not the identity, and it is not the input: a stub that
     * returned its input would pass a round-trip check and fail this. */
    WT_EXPECT_INT("the block changed", 0, memcmp(out, in, 16U) == 0 ? 1 : 0);
  }

  /* RFC 8439 section 2.3.2: the ChaCha20 block function, used as the header
   * protection collision case. The test is that the keystream is the published
   * one when XORed over zeros. */
  {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t zeros[64] = {0};
    uint8_t out[64];
    uint8_t want[64];
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
          key, sizeof(key));
    unhex("000000090000004a00000000", nonce, sizeof(nonce));
    unhex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
          "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
          want, sizeof(want));
    WT_EXPECT_OK("the ChaCha20 keystream vector",
                 wt_chacha20_xor(key, nonce, 1U, zeros, sizeof(zeros), out));
    WT_EXPECT_BYTES("and it is the published value", want, out, sizeof(out));
    /* XORing twice returns the input, which is the property header protection
     * relies on for the mask being a keystream. */
    {
      uint8_t back[64];
      WT_EXPECT_OK("and XORs back",
                   wt_chacha20_xor(key, nonce, 1U, out, sizeof(out), back));
      WT_EXPECT_BYTES("to zeros", zeros, back, sizeof(back));
    }
  }

  /* The refusals. */
  {
    uint8_t block[16] = {0};
    WT_EXPECT_STATUS("a NULL key is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_aes128_ecb_encrypt_block(NULL, block, block));
    WT_EXPECT_STATUS("a NULL input is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_aes128_ecb_encrypt_block(block, NULL, block));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_aes128_ecb_encrypt_block(block, block, NULL));
  }
  WT_EXPECT_STATUS("a NULL input is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_chacha20_xor(NULL, NULL, 0U, NULL, 0U, NULL));
}

static void test_constant_time_and_zero(void) {
  uint8_t a[16];
  uint8_t b[16];
  size_t i;
  size_t bit;

  memset(a, 0x5aU, sizeof(a));
  memcpy(b, a, sizeof(b));
  WT_EXPECT_INT("equal buffers compare equal", 1, wt_ct_equal(a, b, 16U));

  /* Every single-bit difference must be found, not just the first byte's. A
   * comparison that stopped early would still pass this if only the first byte
   * were changed, so every byte and every bit is tried. */
  for (i = 0U; i < 16U; i++) {
    for (bit = 0U; bit < 8U; bit++) {
      uint8_t damaged[16];
      memcpy(damaged, a, sizeof(damaged));
      damaged[i] ^= (uint8_t)(1U << bit);
      WT_EXPECT_INT("a one-bit difference is found", 0,
                    wt_ct_equal(a, damaged, 16U));
    }
  }
  WT_EXPECT_INT("a zero length compares equal", 1, wt_ct_equal(a, b, 0U));
  WT_EXPECT_INT("a NULL side is not equal", 0, wt_ct_equal(NULL, b, 16U));
  WT_EXPECT_INT("a NULL side is not equal the other way", 0,
                wt_ct_equal(a, NULL, 16U));

  /* Zeroing, checked through a re-read rather than by trusting the call. */
  {
    uint8_t secret[32];
    size_t zeroes = 0U;
    memset(secret, 0xCCU, sizeof(secret));
    wt_secure_zero(secret, sizeof(secret));
    for (i = 0U; i < sizeof(secret); i++) {
      if (secret[i] == 0U) zeroes++;
    }
    WT_EXPECT_U64("every byte was cleared", sizeof(secret), (uint64_t)zeroes);
    /* A NULL buffer and a zero length are no-ops: the bytes that were there
     * must still be there, which is what tells a no-op from a clear. */
    memset(secret, 0xCCU, sizeof(secret));
    wt_secure_zero(NULL, 16U);
    wt_secure_zero(secret, 0U);
    zeroes = 0U;
    for (i = 0U; i < sizeof(secret); i++) {
      if (secret[i] == 0xCCU) zeroes++;
    }
    WT_EXPECT_U64("zeroing NULL and zero clears nothing", sizeof(secret),
                  (uint64_t)zeroes);
  }
}

static void test_random(void) {
  uint8_t a[32];
  uint8_t b[32];
  size_t i;
  size_t differences = 0U;
  size_t all_zero = 0U;

  WT_EXPECT_OK("a first draw", wt_random_bytes(a, sizeof(a)));
  WT_EXPECT_OK("a second draw", wt_random_bytes(b, sizeof(b)));
  for (i = 0U; i < sizeof(a); i++) {
    if (a[i] != b[i]) differences++;
    if (a[i] == 0U) all_zero++;
  }
  /* Two draws of 32 bytes agreeing everywhere would be a generator that is not
   * random, and the chance of it happening by accident is 2^-256. */
  WT_EXPECT_TRUE("two draws differ", differences > 0U);
  WT_EXPECT_TRUE("and a draw is not all zeros", all_zero < sizeof(a));
  WT_EXPECT_OK("a zero-length draw", wt_random_bytes(a, 0U));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_random_bytes(NULL, 4U));
}

int main(void) {
  WT_EXPECT_STATUS("the backend initialises", WT_OK, wt_crypto_init());

  test_sha256();
  test_hmac();
  test_hkdf();
  test_hkdf_expand_label();
  test_aead();
  test_aes_block_and_chacha();
  test_constant_time_and_zero();
  test_random();

  WT_TEST_MAIN_END("wt_crypto");
}
