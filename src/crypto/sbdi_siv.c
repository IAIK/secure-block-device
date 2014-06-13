/*
 * sbdi_siv.c
 *
 *  Created on: Jun 13, 2014
 *      Author: dhein
 */

#include "sbdi_siv.h"
#include "sbdi_err.h"

#include <stdarg.h>
#include <string.h>

void sbdi_siv_decrypt(siv_ctx *ctx, const unsigned char *c, unsigned char *p,
    const int len, unsigned char *counter, const int nad, ...)
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

sbdi_error_t sbdi_siv_encrypt(void *ctx, void *nonce,
    const void *pt, int pt_len, const void *ad, int ad_len, void *ct, void *tag) {
  siv_ctx *s_ctx = (siv_ctx *)ctx;
  const unsigned char *p = (const unsigned char *)pt;
  unsigned char *c = (unsigned char *)ct;
  const int len = (const int)pt_len;
  unsigned char *counter = (unsigned char *)nonce;
  int r = siv_encrypt(s_ctx, p, c, len, counter, 1, ad, ad_len);
  if (r != 1) {
    return SBDI_ERR_CRYPTO_FAIL;
  } else {
    return SBDI_SUCCESS;
  }
}

