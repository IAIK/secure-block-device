/*
 * sbdi_siv.c
 *
 *  Created on: Jun 13, 2014
 *      Author: dhein
 */

#include "sbdi_siv.h"
#include "sbdi_crypto.h"
#include "sbdi_buffer.h"

#include <stdarg.h>
#include <string.h>
#include <assert.h>

#define SBDI_SIV_AD_SIZE (4u + (SBDI_BLOCK_CTR_SIZE))

void sbdi_siv_decrypt_dep(siv_ctx *ctx, const unsigned char *c,
    unsigned char *p, const int len, unsigned char *counter, const int nad, ...)
{
  va_list ap;
  unsigned char *ad;
  int adlen, numad = nad;
  unsigned char ctr[AES_BLOCK_SIZE];

  memcpy(ctr, counter, AES_BLOCK_SIZE);
  siv_aes_ctr(ctx, c, len, p, ctr);
  if (numad) {
    va_start(ap, nad);
    while (numad) {
      ad = (unsigned char *) va_arg(ap, char *);
      adlen = va_arg(ap, int);
      s2v_update(ctx, ad, adlen);
      numad--;
    }
  }
  s2v_final(ctx, p, len, ctr);

  /*
   * the only part of the context that is carried along with
   * subsequent calls to siv_decrypt() are the keys, so reset
   * everything else.
   */
  siv_restart(ctx);
  memcpy(counter, ctr, AES_BLOCK_SIZE);
}

sbdi_error_t sbdi_siv_encrypt(void *ctx, const uint8_t *pt, const int pt_len,
    const sbdi_ctr_128b_t *ctr, uint32_t blk_nbr, uint8_t *ct, sbdi_tag_t tag)
{
  // SIV does not use a nonce, make sure it is null!
  SBDI_CHK_PARAM(
      ctx && pt && pt_len > 0 && ctr && sbdi_block_is_valid_phy(blk_nbr) && ct
          && tag);
  siv_ctx *s_ctx = (siv_ctx *) ctx;
  unsigned char *counter = (unsigned char *) tag;

  uint8_t ad[SBDI_SIV_AD_SIZE];
  memset(ad, 0, SBDI_SIV_AD_SIZE);
  sbdi_buffer_t b;
  // TODO should I move memset into init, or remove memset?
  memset(&b, 0, sizeof(sbdi_buffer_t));

  sbdi_buffer_init(&b, ad, SBDI_SIV_AD_SIZE);
  sbdi_buffer_write_uint32_t(&b, blk_nbr);
  sbdi_buffer_write_ctr_128b(&b, ctr);

  int r = siv_encrypt(s_ctx, pt, ct, pt_len, counter, 1, ad, SBDI_SIV_AD_SIZE);
  if (r != 1) {
    return SBDI_ERR_CRYPTO_FAIL;
  } else {
    return SBDI_SUCCESS;
  }
}

sbdi_error_t sbdi_siv_decrypt(void *ctx, const uint8_t *ct, const int ct_len,
    const sbdi_ctr_pkd_t ctr, const uint32_t blk_nbr, uint8_t *pt,
    const sbdi_tag_t tag)
{
  SBDI_CHK_PARAM(
      ctx && ct && ct_len > 0 && ctr && sbdi_block_is_valid_phy(blk_nbr) && pt
          && tag);
  siv_ctx *s_ctx = (siv_ctx *) ctx;
  unsigned char *counter = (unsigned char *) tag;

  uint8_t ad[SBDI_SIV_AD_SIZE];
  memset(ad, 0, SBDI_SIV_AD_SIZE);
  sbdi_buffer_t b;
  // TODO should I move memset into init, or remove memset?
  memset(&b, 0, sizeof(sbdi_buffer_t));

  sbdi_buffer_init(&b, ad, SBDI_SIV_AD_SIZE);
  sbdi_buffer_write_uint32_t(&b, blk_nbr);
  sbdi_buffer_write_bytes(&b, ctr, SBDI_BLOCK_CTR_SIZE);

  int r = siv_decrypt(s_ctx, ct, pt, ct_len, counter, 1, ad, SBDI_SIV_AD_SIZE);
  if (r != 1) {
    return SBDI_ERR_TAG_MISMATCH;
  } else {
    return SBDI_SUCCESS;
  }
}

sbdi_error_t sbdi_siv_cmac(void *ctx, const unsigned char *msg, const int mlen,
    unsigned char *C, const unsigned char *ad, const int ad_len)
{
  SBDI_CHK_PARAM(ctx && msg && mlen > 0 && C && ad && ad_len > 0);
  siv_ctx *s_ctx = (siv_ctx *) ctx;
  sbdi_bl_aes_cmac(s_ctx, ad, ad_len, msg, mlen, C);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_siv_init(siv_ctx *ctx, const sbdi_key_t key)
{
  SBDI_CHK_PARAM(ctx && key);
  memset(ctx, 0, sizeof(siv_ctx));
  int cr = siv_init(ctx, key, SIV_256);
  if (cr == -1) {
    return SBDI_ERR_CRYPTO_FAIL;
  } else {
    return SBDI_SUCCESS;
  }
}

void sbdi_siv_clear(siv_ctx *ctx)
{
  memset(ctx, 0, sizeof(siv_ctx));
}

sbdi_error_t sbdi_siv_create(sbdi_crypto_t **crypto, const sbdi_key_t key)
{
  // The following is a sanity check required by the encrypt and decrypt fun.
  assert(sizeof(sbdi_tag_t) == AES_BLOCK_SIZE);
  SBDI_CHK_PARAM(crypto && key);
  sbdi_error_t r = SBDI_ERR_UNSPECIFIED;
  siv_ctx *ctx = calloc(1, sizeof(siv_ctx));
  if (!ctx) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  r = sbdi_siv_init(ctx, key);
  if (r != SBDI_SUCCESS) {
    goto FAIL;
  }
  sbdi_crypto_t *c = calloc(1, sizeof(sbdi_crypto_t));
  if (!c) {
    r = SBDI_ERR_OUT_Of_MEMORY;
    goto FAIL;
  }
  c->ctx = ctx;
  c->enc = &sbdi_siv_encrypt;
  c->dec = &sbdi_siv_decrypt;
  c->mac = &sbdi_siv_cmac;
  *crypto = c;
  return SBDI_SUCCESS;

  FAIL: if (ctx) {
    sbdi_siv_clear(ctx);
    free(ctx);
  }
  return r;
}

void sbdi_siv_destroy(sbdi_crypto_t *crypto)
{
  if (crypto) {
    assert(crypto->ctx);
    sbdi_siv_clear(crypto->ctx);
    free(crypto->ctx);
    memset(crypto, 0, sizeof(sbdi_crypto_t));
    free(crypto);
  }
}
