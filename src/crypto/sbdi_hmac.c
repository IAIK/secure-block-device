//
// sbdi_hmac.c
//
//  * Block encryption with AES-CBC
//  * Block tags via HMAC-SHA256
//

#include "sbdi_hmac.h"
#include "sbdi_buffer.h"
#include "aes.h"

// Pull-in the SHA implementation from the merkle tree
#include "../../../merkle-tree/src/sha.h"

#include <stdlib.h>
#include <string.h>

// Define as non-zero the create insecure tags and/or IVs (for testing)
#define SBDI_HMAC_INSECURE_TAG     0
#define SBDI_HMAC_INSECURE_IV      0
#define SBDI_HMAC_INSECURE_CIPHER  0

// Define as non-zero to enable memory zeroization code
#define SBDI_HMAC_ZEROIZE_MEMORY   0

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE  32

#define SBDI_HMAC_MAX(a,b) ((a) > (b) ? (a) : (b))
#define SBDI_HMAC_MIN(a,b) ((a) < (b) ? (a) : (b))

#if SBDI_HMAC_ZEROIZE_MEMORY
# define SBDI_STMT_ZEROIZE(stmt) do { stmt; } while(0)
#else
# define SBDI_STMT_ZEROIZE(stmt) do { } while(0)
#endif

typedef struct sbdi_cbc_hmac {
  AES_KEY dec_key;
  AES_KEY enc_key;
  uint8_t mac_master_key[SHA256_HASH_SIZE];
} sbdi_cbc_hmac_t;

#define SHA256_CHECKED(expr)                    \
  do {                                          \
    if ((expr) != shaSuccess) {                 \
      goto fail;                                \
    }                                           \
  } while(0)

//----------------------------------------------------------------------
// HMAC-SHA256
//
static sbdi_error_t sbdi_hmac_sha256(uint8_t mac[SHA256_HASH_SIZE],
                                     const uint8_t *data0, size_t data0_len,
                                     const uint8_t *data1, size_t data1_len,
                                     const uint8_t *ukey, size_t ukey_len)
{
  uint8_t pad[SHA256_BLOCK_SIZE];
  SHA256Context md;

  // Key scheduling
  memset(pad, 0, SHA256_BLOCK_SIZE);

  if (ukey_len > SHA256_BLOCK_SIZE) {
    // key = H(ukey) || [0x00 ...]
    SHA256_CHECKED(SHA256Reset(&md));
    SHA256_CHECKED(SHA256Input(&md, ukey, ukey_len));
    SHA256_CHECKED(SHA256Result(&md, pad));

  } else {
    // key = ukey || [0x00 ..]
    memcpy(pad, ukey, ukey_len);
  }

  // Setup ipad = key ^ 0x36
  for (size_t i = 0; i < SHA256_BLOCK_SIZE; ++i) {
    pad[i] ^= 0x36;
  }

  // Compute the inner hash
  SHA256_CHECKED(SHA256Reset(&md));
  SHA256_CHECKED(SHA256Input(&md, pad, SHA256_BLOCK_SIZE));
  if (data0_len > 0) {
    SHA256_CHECKED(SHA256Input(&md, data0, data0_len));
  }
  if (data1_len > 0) {
    SHA256_CHECKED(SHA256Input(&md, data1, data1_len));
  }
  SHA256_CHECKED(SHA256Result(&md, mac));

  // Setup opad = key ^ 0x5C = ipad ^ (0x5C ^ 0x36)
  for (size_t i = 0; i < SHA256_BLOCK_SIZE; ++i) {
    pad[i] ^= (0x36 ^ 0x5C);
  }

  // Compute the outer hash
  SHA256_CHECKED(SHA256Reset(&md));
  SHA256_CHECKED(SHA256Input(&md, pad, SHA256_BLOCK_SIZE));
  SHA256_CHECKED(SHA256Input(&md, mac, SHA256_HASH_SIZE));
  SHA256_CHECKED(SHA256Result(&md, mac));

  // Cleanup
  SBDI_STMT_ZEROIZE(memset(pad, 0, SHA256_BLOCK_SIZE));
  SBDI_STMT_ZEROIZE(memset(&md, 0, sizeof(SHA256Context)));
  return SBDI_SUCCESS;

 fail:
  SBDI_STMT_ZEROIZE(memset(pad, 0, SHA256_BLOCK_SIZE));
  SBDI_STMT_ZEROIZE(memset(&md, 0, sizeof(SHA256Context)));
  SBDI_STMT_ZEROIZE(memset(mac, 0, SHA256_HASH_SIZE));
  return SBDI_ERR_UNSPECIFIED;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_hmac_mac(void *pctx, const unsigned char *msg,
    const int mlen, unsigned char *C, const unsigned char *ad, const int ad_len)
{
  sbdi_cbc_hmac_t *ctx = pctx;
  sbdi_error_t ret = SBDI_ERR_UNSPECIFIED;
  uint8_t mac[SHA256_HASH_SIZE];

  assert(ctx);
  SBDI_CHK_PARAM(msg && mlen > 0 && C);

  // Clear the tag
  memset(C, 0, SBDI_BLOCK_TAG_SIZE);

  // Compute the tag as HMAC_{K_mac}(ad || msg)
  ret = sbdi_hmac_sha256(mac, ad, ad_len, msg, mlen,
                         ctx->mac_master_key, SHA256_HASH_SIZE);
  if (ret != SBDI_SUCCESS) {
    goto fail;
  }

  // Success, copy the MAC (truncate/zero-extend if needed)
  memcpy(C, mac, SBDI_HMAC_MIN(SHA256_HASH_SIZE, SBDI_BLOCK_TAG_SIZE));
  ret = SBDI_SUCCESS;

 fail:
  return ret;
}

//----------------------------------------------------------------------
static sbdi_error_t sbdi_hmac_sha256_tag(uint8_t tag[SBDI_BLOCK_TAG_SIZE],
                                         sbdi_cbc_hmac_t *ctx,
                                         const uint8_t *ct, size_t ct_len,
                                         const uint8_t iv[AES_BLOCK_SIZE])
{
#if SBDI_HMAC_INSECURE_TAG
  // For testing: Always generate all zero tags
  memset(tag, 0xFF, SBDI_BLOCK_TAG_SIZE);
  return SBDI_SUCCESS;

#else
  // Compute the block tag: tag = HMAC_{K_mac}(IV || CT)
  //
  // * The construction of the IV (sbdi_hmac_aes_iv) cryptographically
  //   binds the tag to the block update counter and the block number.
  //
  return sbdi_hmac_mac(ctx, ct, ct_len, tag, iv, AES_BLOCK_SIZE);
#endif
}

//----------------------------------------------------------------------
static sbdi_error_t sbdi_hmac_aes_iv(uint8_t iv[AES_BLOCK_SIZE],
                                     sbdi_cbc_hmac_t *ctx,
                                     const sbdi_ctr_128b_t *ctr, uint32_t blk_nbr)
{
#if SBDI_HMAC_INSECURE_IV
  // For testing: Always generate all zero IVs
  memset(iv, 0, AES_BLOCK_SIZE);
  return SBDI_SUCCESS;

#else
  // Derive a pseudo-random IV by encrypting the block update counter
  // (ctr) and the block number (blk_nbr) with AES under K_enc.
  //
  // Plaintext for IV generation:
  //   +-----------------------+-----------+
  //   | blk_nbr ^ ctr[127:96] | ctr[95:0] |
  //   +-----------------------+-----------+
  //
  // IV = AES_{K_enc}([blk_nbr ^ ctr[127:96]] || ctr[95:0])
  //
  // * We don't need to store the IVs since the can be recomputed on-demand
  //   via a single AES encryption operation.
  //
  // * The block update counter (ctr) is incremented by the SBD whenever the
  //   block changes. This ensures that we won't reuse any IVs (at least not
  //   before we hit 2^96 updates).
  //
  assert(AES_BLOCK_SIZE == 4 * sizeof(uint32_t));

  sbdi_buffer_t b;
  sbdi_buffer_init(&b, iv, AES_BLOCK_SIZE);
  sbdi_buffer_write_uint32_t(&b, (uint32_t) (ctr->hi >> 32) ^ blk_nbr);
  sbdi_buffer_write_uint32_t(&b, (uint32_t) (ctr->hi));
  sbdi_buffer_write_uint64_t(&b, (uint64_t) ctr->lo);
  AES_encrypt(iv, iv, &ctx->enc_key);
  return SBDI_SUCCESS;
#endif
}

//----------------------------------------------------------------------
static sbdi_error_t sbdi_hmac_encrypt(void *pctx, const uint8_t *pt,
                                      const int pt_len,
                                      const sbdi_ctr_128b_t *ctr,
                                      uint32_t blk_nbr, uint8_t *ct,
                                      sbdi_tag_t tag)
{
  sbdi_cbc_hmac_t *ctx = pctx;
  uint8_t iv[AES_BLOCK_SIZE];
  sbdi_error_t ret;
  assert(ctx);
  SBDI_CHK_PARAM(pt && ctr && pt_len > 0 && tag);

  // Prepare the IV (dependent on K_enc, ctr and blk_nbr)
  sbdi_hmac_aes_iv(iv, ctx, ctr, blk_nbr);


#if SBDI_HMAC_INSECURE_CIPHER
  // Dummy encryption (for testing)
  memmove(ct, pt, pt_len);
#else
  // CAVEAT EMPTOR: AES_cbc_encrypt destroys the original iv
  // during the process ... we, however, need it later on as AD
  // for tag computation.
  uint8_t iv_copy[AES_BLOCK_SIZE];
  memcpy(iv_copy, iv, AES_BLOCK_SIZE);

  // Encrypt the block (we use AES CBC for simplicity)
  AES_cbc_encrypt(pt, ct, pt_len, &ctx->enc_key, iv_copy, 1);
#endif

  // Create the authentication tag (given the IV and ciphertext)
  ret = sbdi_hmac_sha256_tag(tag, ctx, ct, pt_len, iv);
  if (ret != SBDI_SUCCESS) {
    goto fail;
  }

  ret = SBDI_SUCCESS;

 fail:
  return ret;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_hmac_decrypt(void *pctx, const uint8_t *ct,
    const int ct_len, const sbdi_ctr_pkd_t ctr, const uint32_t blk_nbr,
    uint8_t *pt, const sbdi_tag_t tag)
{
  sbdi_cbc_hmac_t *ctx = pctx;
  uint8_t iv[AES_BLOCK_SIZE];
  sbdi_tag_t expected_tag;
  sbdi_error_t ret;
  assert(pctx);
  SBDI_CHK_PARAM(
      ct && ct_len > 0 && ctr && sbdi_block_is_valid_phy(blk_nbr) && pt && tag);

  // Prepare the IV (dependent on K_enc, ctr and blk_nbr)
  // FIXME: Counter type safety?
  sbdi_hmac_aes_iv(iv, ctx, (const  sbdi_ctr_128b_t *) ctr, blk_nbr);

  // Recompute the expected authentication tag (authenticate IV and ciphertext)
  ret = sbdi_hmac_sha256_tag(expected_tag, ctx, ct, ct_len, iv);
  if (ret != SBDI_SUCCESS) {
    goto fail;
  }

  // Verify the authentication tag
  if (memcmp(tag, expected_tag, sizeof(sbdi_tag_t)) != 0) {
    ret = SBDI_ERR_TAG_MISMATCH;
    goto fail;
  }

#if SBDI_HMAC_INSECURE_CIPHER
  // Dummy encryption (for testing)
  memmove(pt, ct, ct_len);
#else
  // Decrypt the block (after IV and ciphertext have been authenticated)
  AES_cbc_encrypt(ct, pt, ct_len, &ctx->dec_key, iv, 0);
#endif

  ret = SBDI_SUCCESS;

 fail:
  SBDI_STMT_ZEROIZE(memset(expected_tag, 0, sizeof(sbdi_tag_t)));
  return ret;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_hmac_create(sbdi_crypto_t **crypto, const sbdi_key_t key)
{
  assert(sizeof(sbdi_tag_t) == AES_BLOCK_SIZE);
  SBDI_CHK_PARAM(crypto && key);

  sbdi_error_t r = SBDI_ERR_UNSPECIFIED;
  sbdi_cbc_hmac_t *ctx = calloc(1, sizeof(sbdi_cbc_hmac_t));
  if (!ctx) {
    r = SBDI_ERR_OUT_Of_MEMORY;
    goto err_out;
  }

  // Schedule the AES encryption and decryption key (K_enc)
  if (AES_set_encrypt_key(key, sizeof(sbdi_key_t) * 8, &ctx->enc_key) != 0 ||
      AES_set_decrypt_key(key, sizeof(sbdi_key_t) * 8, &ctx->dec_key) != 0) {
    r = SBDI_ERR_UNSPECIFIED;
    goto fail;
  }

  // Derive a master key K_mac for computing the block MACs
  // (we just hash the AES encryption key for this purpose)
  SHA256Context md;
  SHA256_CHECKED(SHA256Reset(&md));
  SHA256_CHECKED(SHA256Input(&md, key, sizeof(sbdi_key_t)));
  SHA256_CHECKED(SHA256Result(&md, ctx->mac_master_key));

  sbdi_crypto_t *c = calloc(1, sizeof(sbdi_crypto_t));
  if (!c) {
    r = SBDI_ERR_OUT_Of_MEMORY;
    goto fail;
  }
  c->ctx = ctx;
  c->enc = &sbdi_hmac_encrypt;
  c->dec = &sbdi_hmac_decrypt;
  c->mac = &sbdi_hmac_mac;
  *crypto = c;
  return SBDI_SUCCESS;

 fail:
  SBDI_STMT_ZEROIZE(memset(&md, 0, sizeof(md)));
  SBDI_STMT_ZEROIZE(memset(ctx, 0, sizeof(sbdi_cbc_hmac_t)));
  free(ctx);

 err_out:
  return r;
}

//----------------------------------------------------------------------
void sbdi_hmac_destroy(sbdi_crypto_t *crypto)
{
  if (crypto) {
    assert(crypto->ctx);
    SBDI_STMT_ZEROIZE(memset(crypto->ctx, 0, sizeof(sbdi_cbc_hmac_t)));
    free(crypto->ctx);

    SBDI_STMT_ZEROIZE(memset(crypto, 0, sizeof(sbdi_crypto_t)));
    free(crypto);
  }
}
