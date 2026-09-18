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

#include "test_crypto_aead_support.h"
#include "webtransport/crypto/crypto.h"

/* Hex to bytes, for the vectors below. A local helper rather than a large
 * transcription: the strings are copied from the documents and this is the only
 * thing that has to be right about them. */

static void test_sha256(void) {
  uint8_t out[WT_SHA256_LEN];
  uint8_t want[WT_SHA256_LEN];

  /* NIST's SHA-256 of "abc". */
  WT_EXPECT_OK("sha256 of abc", wt_sha256("abc", 3U, out));
  unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* The empty string, which is the hash the TLS 1.3 key schedule takes
   * "derived" from. */
  WT_EXPECT_OK("sha256 of nothing", wt_sha256("", 0U, out));
  unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* A 56-byte message, which is one byte short of the block boundary and is
   * where a padding implementation first goes wrong. */
  WT_EXPECT_OK("sha256 of 56 bytes",
               wt_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56U, out));
  unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* The streaming interface must agree with the one-shot, including for a
   * message written in two pieces across the block boundary. */
  {
    wt_sha256_ctx_t ctx;
    uint8_t one_shot[WT_SHA256_LEN];
    WT_EXPECT_OK("a context starts", wt_sha256_init(&ctx));
    WT_EXPECT_OK("and takes a first piece",
                 wt_sha256_update(&ctx, "abcdbcdecdefdefgefghfghighijhijk", 32U));
    WT_EXPECT_OK("and a second", wt_sha256_update(&ctx, "ijkljklmklmnlmnomnopnopq", 24U));
    WT_EXPECT_OK("and finishes", wt_sha256_final(&ctx, out));
    WT_EXPECT_OK("the one-shot agrees", wt_sha256("abcdbcdecdefdefgefghfghighijhijk"
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
    unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want_abc,
          sizeof(want_abc));
    unhex("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721", want_abcdef,
          sizeof(want_abcdef));
    WT_EXPECT_OK("a snapshot context starts", wt_sha256_init(&ctx));
    WT_EXPECT_OK("and takes the first half", wt_sha256_update(&ctx, "abc", 3U));
    WT_EXPECT_OK("the hash so far", wt_sha256_snapshot(&ctx, so_far));
    WT_EXPECT_BYTES("is the hash of the first half", want_abc, so_far, WT_SHA256_LEN);
    /* Reading it twice gives the same answer, and the context still absorbs. */
    WT_EXPECT_OK("read again", wt_sha256_snapshot(&ctx, so_far));
    WT_EXPECT_BYTES("to the same value", want_abc, so_far, WT_SHA256_LEN);
    WT_EXPECT_OK("the context takes the second half", wt_sha256_update(&ctx, "def", 3U));
    WT_EXPECT_OK("and finalises", wt_sha256_final(&ctx, rest));
    WT_EXPECT_BYTES("to the whole message's hash", want_abcdef, rest, WT_SHA256_LEN);
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
  WT_EXPECT_STATUS("a NULL context is refused", WT_ERR_INVALID_ARGUMENT, wt_sha256_init(NULL));
  WT_EXPECT_STATUS("snapshotting a NULL context is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_sha256_snapshot(NULL, out));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT, wt_sha256("abc", 3U, NULL));
  WT_EXPECT_STATUS("NULL data with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_sha256(NULL, 3U, out));
  /* A NULL output on the STREAMING path is the same refusal the one-shot `wt_sha256` above applies and the ten
   * other entry points in the backend apply. It used to be missing, and the pointer went straight into
   * EVP_DigestFinal_ex: the process died inside libcrypto rather than returning a status, which a caller can
   * only read as "the library crashed on a NULL I was told was refused everywhere else". The context is a live
   * one here, so the check that fires is the argument check and not the state check. */
  {
    wt_sha256_ctx_t live;
    WT_EXPECT_OK("a context for the NULL-output case", wt_sha256_init(&live));
    WT_EXPECT_OK("which has absorbed something", wt_sha256_update(&live, "abc", 3U));
    WT_EXPECT_STATUS("finalising into NULL is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_sha256_final(&live, NULL));
    /* And the refusal left the context usable, which is the other half of telling a caller its argument was
     * wrong rather than that its data was lost. */
    WT_EXPECT_OK("the one-shot hash of the same bytes", wt_sha256("abc", 3U, want));
    WT_EXPECT_OK("and the context still finalises", wt_sha256_final(&live, out));
    WT_EXPECT_BYTES("to the hash of what it absorbed", want, out, WT_SHA256_LEN);
  }
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
    WT_EXPECT_STATUS("updating a context that holds something else is refused", WT_ERR_STATE,
                     wt_sha256_update(&ctx, "a", 1U));
    WT_EXPECT_STATUS("finalising it is refused", WT_ERR_STATE, wt_sha256_final(&ctx, out));
  }
}

static void test_hmac(void) {
  uint8_t out[WT_SHA256_LEN];
  uint8_t want[WT_SHA256_LEN];
  uint8_t key[131];

  /* RFC 4231 test case 1: a 20-byte key of 0x0b and "Hi There". */
  memset(key, 0x0b, 20U);
  WT_EXPECT_OK("RFC 4231 case 1", wt_hmac_sha256(key, 20U, (const uint8_t *)"Hi There", 8U, out));
  unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* Case 2: a short key, "Jefe". */
  WT_EXPECT_OK("RFC 4231 case 2",
               wt_hmac_sha256((const uint8_t *)"Jefe", 4U,
                              (const uint8_t *)"what do ya want for nothing?", 28U, out));
  unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", want, sizeof(want));
  WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);

  /* Case 6: a 131-byte key, which is longer than the block size and so must be
   * hashed first -- the case a naive implementation gets wrong. The message is
   * the RFC's, and its length is checked against the length the RFC states so
   * that a typo here cannot quietly make the vector mean something else. */
  {
    static const char message[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    memset(key, 0xaa, 131U);
    WT_EXPECT_U64("RFC 4231 case 6's message length", 54U, (uint64_t)(sizeof(message) - 1U));
    WT_EXPECT_OK("RFC 4231 case 6",
                 wt_hmac_sha256(key, 131U, (const uint8_t *)message, sizeof(message) - 1U, out));
    unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", want, sizeof(want));
    WT_EXPECT_BYTES("and it is the published value", want, out, WT_SHA256_LEN);
  }

  /* Case 7: a 131-byte key and a 152-byte message. */
  {
    static const char message[] =
        "This is a test using a larger than block-size key and a larger than "
        "block-size data. The key needs to be hashed before being used by the "
        "HMAC algorithm.";
    memset(key, 0xaa, 131U);
    WT_EXPECT_U64("RFC 4231 case 7's message length", 152U, (uint64_t)(sizeof(message) - 1U));
    WT_EXPECT_OK("RFC 4231 case 7",
                 wt_hmac_sha256(key, 131U, (const uint8_t *)message, sizeof(message) - 1U, out));
    unhex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", want, sizeof(want));
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
    static const uint8_t ikm[22] = {0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU};
    uint8_t salt[13];
    uint8_t info[10];
    size_t i;
    for (i = 0U; i < sizeof(salt); i++)
      salt[i] = (uint8_t)i;
    for (i = 0U; i < sizeof(info); i++)
      info[i] = (uint8_t)(0xf0U + i);

    WT_EXPECT_OK("RFC 5869 case 1 extracts",
                 wt_hkdf_extract_sha256(salt, sizeof(salt), ikm, sizeof(ikm), prk));
    unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", want, 32U);
    WT_EXPECT_BYTES("and the PRK is the published value", want, prk, WT_SHA256_LEN);

    WT_EXPECT_OK("and expands",
                 wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, info, sizeof(info), okm, 42U));
    unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865",
          want, 42U);
    WT_EXPECT_BYTES("and the OKM is the published value", want, okm, 42U);
  }

  /* Case 3: no salt and no info, which is the case the TLS 1.3 schedule uses for
   * the early secret and where "no salt" must mean a zero salt of hash length. */
  {
    static const uint8_t ikm[22] = {0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
                                    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU};
    WT_EXPECT_OK("RFC 5869 case 3 extracts with no salt",
                 wt_hkdf_extract_sha256(NULL, 0U, ikm, sizeof(ikm), prk));
    unhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", want, 32U);
    WT_EXPECT_BYTES("and the PRK is the published value", want, prk, WT_SHA256_LEN);
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
                 wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, NULL, 0U, large, sizeof(large)));
    WT_EXPECT_STATUS(
        "one byte more is refused", WT_ERR_INVALID_ARGUMENT,
        wt_hkdf_expand_sha256(prk, WT_SHA256_LEN, NULL, 0U, large, sizeof(large) + 1U));
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
        0x9aU, 0xc3U, 0x12U, 0xa7U, 0xf8U, 0x77U, 0x46U, 0x8eU, 0xbeU, 0x69U, 0x42U,
        0x27U, 0x48U, 0xadU, 0x00U, 0xa1U, 0x54U, 0x43U, 0xf1U, 0x82U, 0x03U, 0xa0U,
        0x7dU, 0x60U, 0x60U, 0xf6U, 0x88U, 0xf3U, 0x0fU, 0x21U, 0x63U, 0x2bU};
    WT_EXPECT_OK("quic key from the ChaCha20 secret",
                 wt_hkdf_expand_label_sha256(chacha_secret, sizeof(chacha_secret), "quic key", NULL,
                                             0U, out, 32U));
    unhex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8", want, 32U);
    WT_EXPECT_BYTES("is the RFC's value", want, out, 32U);

    WT_EXPECT_OK("quic iv from the same secret",
                 wt_hkdf_expand_label_sha256(chacha_secret, sizeof(chacha_secret), "quic iv", NULL,
                                             0U, out, 12U));
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
                                             (const uint8_t *)"abc", 3U, with_context, 32U));
    WT_EXPECT_OK("without one", wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic key",
                                                            NULL, 0U, without_context, 32U));
    WT_EXPECT_INT("the two differ", 0, memcmp(with_context, without_context, 32U) == 0 ? 1 : 0);
  }

  /* The label is prefixed with "tls13 ": a derivation under a label and under a
   * label with that prefix already in it must differ, which they would not if the
   * prefix were being dropped. */
  {
    uint8_t a[32];
    uint8_t b[32];
    memset(secret, 0x11, sizeof(secret));
    WT_EXPECT_OK("label quic key",
                 wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic key", NULL, 0U, a, 32U));
    WT_EXPECT_OK(
        "label tls13 quic key",
        wt_hkdf_expand_label_sha256(secret, sizeof(secret), "tls13 quic key", NULL, 0U, b, 32U));
    WT_EXPECT_INT("the two differ", 0, memcmp(a, b, 32U) == 0 ? 1 : 0);
  }

  /* The output length is part of the expansion, not a truncation: a 16-byte
   * expansion of a secret is not the first 16 bytes of its 32-byte expansion.
   * This is the defect RFC 9001's header protection key length turned on. */
  {
    uint8_t short_out[16];
    uint8_t long_out[32];
    memset(secret, 0x77, sizeof(secret));
    WT_EXPECT_OK(
        "a 16-byte expansion",
        wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic hp", NULL, 0U, short_out, 16U));
    WT_EXPECT_OK(
        "a 32-byte expansion",
        wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic hp", NULL, 0U, long_out, 32U));
    WT_EXPECT_INT("which is not its prefix", 0, memcmp(short_out, long_out, 16U) == 0 ? 1 : 0);
  }

  /* Refusals: a label too long for its own length prefix, a context above 255,
   * and NULL arguments. */
  {
    char long_label[260];
    memset(long_label, 'a', sizeof(long_label) - 1U);
    long_label[sizeof(long_label) - 1U] = '\0';
    WT_EXPECT_STATUS(
        "a 259-byte label is refused", WT_ERR_INVALID_ARGUMENT,
        wt_hkdf_expand_label_sha256(secret, sizeof(secret), long_label, NULL, 0U, out, 32U));
    WT_EXPECT_STATUS(
        "a 256-byte context is refused", WT_ERR_INVALID_ARGUMENT,
        wt_hkdf_expand_label_sha256(secret, sizeof(secret), "quic key", secret, 256U, out, 32U));
    WT_EXPECT_STATUS("a NULL secret is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(NULL, 32U, "quic key", NULL, 0U, out, 32U));
    WT_EXPECT_STATUS("a NULL label is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(secret, 32U, NULL, NULL, 0U, out, 32U));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_hkdf_expand_label_sha256(secret, 32U, "quic key", NULL, 0U, NULL, 32U));
    /* A 255-byte context is allowed, and a 249-byte label. */
    {
      uint8_t context[255];
      char label[250];
      memset(context, 0x5aU, sizeof(context));
      memset(label, 'b', 249U);
      label[249] = '\0';
      WT_EXPECT_OK(
          "a 255-byte context is allowed",
          wt_hkdf_expand_label_sha256(secret, 32U, "quic key", context, sizeof(context), out, 32U));
      WT_EXPECT_OK("a 249-byte label is allowed",
                   wt_hkdf_expand_label_sha256(secret, 32U, label, NULL, 0U, out, 32U));
    }
  }
}
int main(void) {
  test_sha256();
  test_hmac();
  test_hkdf();
  test_hkdf_expand_label();
  WT_TEST_MAIN_END("test_crypto");
}
