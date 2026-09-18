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
#include "test_crypto_aead_support.h"


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
    WT_EXPECT_OK("an empty plaintext seals",
                 wt_aead_seal(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, NULL, 0U, out, tag));
    unhex("58e2fccefa7e3061367f1d57a4e7455a", want, sizeof(want));
    WT_EXPECT_BYTES("and the tag is the published value", want, tag, WT_AEAD_TAG_LEN);

    /* The same tag opens it, and a tag that is not this one does not. */
    WT_EXPECT_OK("and the same tag opens it",
                 wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, NULL, 0U, tag, out));
    tag[0] ^= 0x01U;
    WT_EXPECT_STATUS("and a one-bit difference does not", WT_ERR_AUTHENTICATION,
                     wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, NULL, 0U, tag, out));
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
    WT_EXPECT_OK("a block of zeros seals", wt_aead_seal(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U,
                                                        plain, sizeof(plain), cipher, tag));
    unhex("0388dace60b6a392f328c2b971b2fe78", want_cipher, 16U);
    unhex("ab6e47d42cec13bdf53a67b21257bddf", want_tag, sizeof(want_tag));
    WT_EXPECT_BYTES("and the ciphertext is the published value", want_cipher, cipher, 16U);
    WT_EXPECT_BYTES("and so is the tag", want_tag, tag, WT_AEAD_TAG_LEN);
    WT_EXPECT_OK("and it opens", wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, cipher,
                                              sizeof(cipher), tag, back));
    WT_EXPECT_BYTES("to the plaintext that was sealed", plain, back, sizeof(back));
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
                 wt_aead_seal(WT_AEAD_AES_128_GCM, key, iv, aad, sizeof(aad), plain, sizeof(plain),
                              cipher, tag));
    WT_EXPECT_BYTES("and the ciphertext is the published value", want_cipher, cipher,
                    sizeof(cipher));
    WT_EXPECT_BYTES("and so is the tag", want_tag, tag, WT_AEAD_TAG_LEN);

    /* It opens, in place, back to the published plaintext. */
    memcpy(back, cipher, sizeof(back));
    WT_EXPECT_OK("and it opens in place", wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, aad,
                                                       sizeof(aad), back, sizeof(back), tag, back));
    WT_EXPECT_BYTES("back to the plaintext", plain, back, sizeof(back));

    /* A single flipped bit in the ciphertext must be refused, and the plaintext
     * buffer must hold nothing afterwards: that is the property the API exists
     * for, and a caller that ignored the status would find no bytes to misuse. */
    {
      uint8_t damaged[60];
      size_t nonzero = 0U;
      memcpy(damaged, cipher, sizeof(damaged));
      damaged[7] ^= 0x01U;
      WT_EXPECT_STATUS("a flipped ciphertext bit is refused", WT_ERR_AUTHENTICATION,
                       wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, aad, sizeof(aad), damaged,
                                    sizeof(damaged), tag, damaged));
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
                       wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, other_aad, sizeof(other_aad),
                                    cipher, sizeof(cipher), tag, out));
    }
    /* A truncated tag is a different tag: the last byte of the AAD's tag is
     * compared, not just the first. */
    {
      uint8_t short_tag[WT_AEAD_TAG_LEN];
      uint8_t out[60];
      memcpy(short_tag, tag, sizeof(short_tag));
      short_tag[WT_AEAD_TAG_LEN - 1U] ^= 0x80U;
      WT_EXPECT_STATUS("a damaged final tag byte is refused", WT_ERR_AUTHENTICATION,
                       wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, aad, sizeof(aad), cipher,
                                    sizeof(cipher), short_tag, out));
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
    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, sizeof(key));
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
                 wt_aead_seal(WT_AEAD_CHACHA20_POLY1305, key, iv, aad, sizeof(aad), plain,
                              sizeof(plain), cipher, tag));
    WT_EXPECT_BYTES("with the published tag", want_tag, tag, WT_AEAD_TAG_LEN);
    WT_EXPECT_BYTES("and the published ciphertext", want_cipher, cipher, sizeof(cipher));
    WT_EXPECT_OK("and it opens", wt_aead_open(WT_AEAD_CHACHA20_POLY1305, key, iv, aad, sizeof(aad),
                                              cipher, sizeof(cipher), tag, back));
    WT_EXPECT_BYTES("back to the published plaintext", plain, back, sizeof(back));
    tag[0] ^= 0x01U;
    WT_EXPECT_STATUS("and a damaged tag is refused", WT_ERR_AUTHENTICATION,
                     wt_aead_open(WT_AEAD_CHACHA20_POLY1305, key, iv, aad, sizeof(aad), cipher,
                                  sizeof(cipher), tag, back));
  }

  /* The suite's sizes. */
  WT_EXPECT_U64("AES-128-GCM key", 16U, (uint64_t)wt_aead_key_len(WT_AEAD_AES_128_GCM));
  WT_EXPECT_U64("ChaCha20 key", 32U, (uint64_t)wt_aead_key_len(WT_AEAD_CHACHA20_POLY1305));
  WT_EXPECT_U64("IV length", 12U, (uint64_t)wt_aead_iv_len(WT_AEAD_AES_128_GCM));
  WT_EXPECT_U64("tag length", 16U, (uint64_t)wt_aead_tag_len(WT_AEAD_AES_128_GCM));
  WT_EXPECT_U64("an unknown suite has no key", 0U, (uint64_t)wt_aead_key_len((wt_aead_t)99));
  WT_EXPECT_STR("aes-128-gcm is named", "aes-128-gcm", wt_aead_name(WT_AEAD_AES_128_GCM));
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
                     wt_aead_seal((wt_aead_t)99, key, key, NULL, 0U, out, 1U, out, tag));
    WT_EXPECT_STATUS("an unknown AEAD is refused when opening", WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open((wt_aead_t)99, key, key, NULL, 0U, out, 1U, tag, out));
    WT_EXPECT_STATUS("a NULL tag is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_aead_seal(WT_AEAD_AES_128_GCM, key, key, NULL, 0U, out, 1U, out, NULL));
    WT_EXPECT_STATUS("a NULL tag is refused when opening", WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open(WT_AEAD_AES_128_GCM, key, key, NULL, 0U, out, 1U, NULL, out));
    WT_EXPECT_STATUS("a NULL key is refused when opening", WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open(WT_AEAD_AES_128_GCM, NULL, key, NULL, 0U, out, 1U, tag, out));
    WT_EXPECT_STATUS("a NULL IV is refused when opening", WT_ERR_INVALID_ARGUMENT,
                     wt_aead_open(WT_AEAD_AES_128_GCM, key, NULL, NULL, 0U, out, 1U, tag, out));
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
    WT_EXPECT_OK("the AES-128 block vector", wt_aes128_ecb_encrypt_block(key, in, out));
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
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, sizeof(key));
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
      WT_EXPECT_OK("and XORs back", wt_chacha20_xor(key, nonce, 1U, out, sizeof(out), back));
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
      WT_EXPECT_INT("a one-bit difference is found", 0, wt_ct_equal(a, damaged, 16U));
    }
  }
  WT_EXPECT_INT("a zero length compares equal", 1, wt_ct_equal(a, b, 0U));
  WT_EXPECT_INT("a NULL side is not equal", 0, wt_ct_equal(NULL, b, 16U));
  WT_EXPECT_INT("a NULL side is not equal the other way", 0, wt_ct_equal(a, NULL, 16U));

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
    WT_EXPECT_U64("zeroing NULL and zero clears nothing", sizeof(secret), (uint64_t)zeroes);
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
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT, wt_random_bytes(NULL, 4U));
}

int main(void) {
  test_aead();
  test_aes_block_and_chacha();
  test_constant_time_and_zero();
  test_random();
  WT_TEST_MAIN_END("test_crypto_aead");
}
