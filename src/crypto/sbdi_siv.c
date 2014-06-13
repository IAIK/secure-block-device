/*
 * sbdi_siv.c
 *
 *  Created on: Jun 13, 2014
 *      Author: dhein
 */

#include "sbdi_siv.h"
#include "sbdi_crypto.h"

#include <stdarg.h>
#include <string.h>
#include <assert.h>

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

sbdi_error_t sbdi_siv_encrypt(void *ctx, void *nonce, const void *pt,
    int pt_len, const void *ad, int ad_len, void *ct, void *tag)
{
  // SIV does not use a nonce, make sure it is null!
  SBDI_CHK_PARAM(
      ctx && !nonce && ct && ad && pt && tag && pt_len > 0 && ad_len > 0);
  siv_ctx *s_ctx = (siv_ctx *) ctx;
  const unsigned char *p = (const unsigned char *) pt;
  unsigned char *c = (unsigned char *) ct;
  const int len = (const int) pt_len;
  unsigned char *counter = (unsigned char *) tag;
  int r = siv_encrypt(s_ctx, p, c, len, counter, 1, ad, ad_len);
  if (r != 1) {
    return SBDI_ERR_CRYPTO_FAIL;
  } else {
    return SBDI_SUCCESS;
  }
}

sbdi_error_t sbdi_siv_decrypt(void *ctx, const void *nonce, const void *ct,
    int ct_len, const void *ad, int ad_len, void *pt, const void *tag)
{
  // SIV does not use a nonce, make sure it is null!
  SBDI_CHK_PARAM(
      ctx && !nonce && ct && ad && pt && tag && ct_len > 0 && ad_len > 0);
  siv_ctx *s_ctx = (siv_ctx *) ctx;
  const unsigned char *c = (const unsigned char *) ct;
  unsigned char *p = (unsigned char *) pt;
  const int len = (const int) ct_len;
  unsigned char *counter = (unsigned char *) tag;
  int r = siv_decrypt(s_ctx, c, p, len, counter, 1, ad, ad_len);
  if (r != 1) {
    return SBDI_ERR_TAG_MISMATCH;
  } else {
    return SBDI_SUCCESS;
  }
}

sbdi_error_t sbdi_siv_cmac(void *ctx, const unsigned char *msg,
    const int mlen, unsigned char *C, const unsigned char *ad, const int ad_len) {
  SBDI_CHK_PARAM(ctx && msg && mlen > 0 && C && ad && ad_len > 0);
  siv_ctx *s_ctx = (siv_ctx *)ctx;
  sbdi_bl_aes_cmac(s_ctx, ad, ad_len, msg, mlen, C);
  return SBDI_SUCCESS;
}


sbdi_error_t sbdi_siv_init(siv_ctx *ctx, sbdi_key_t key)
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

sbdi_error_t sbdi_siv_create(sbdi_crypto_t **crypto, sbdi_key_t key)
{
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

void sbdi_siv_destroy(sbdi_crypto_t *crypto) {
  if (crypto) {
    assert(crypto->ctx);
    sbdi_siv_clear(crypto->ctx);
    free(crypto->ctx);
    memset(crypto, 0, sizeof(sbdi_crypto_t));
    free(crypto);
  }
}
