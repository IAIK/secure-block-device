/*
 * sbdi_nocrypto.c
 *
 *  Created on: Jun 17, 2014
 *      Author: dhein
 */

#include "sbdi_nocrypto.h"

#include <stdlib.h>
#include <string.h>

sbdi_error_t sbdi_nocrypto_encrypt(void *ctx, const uint8_t *pt,
    const int pt_len, const sbdi_ctr_128b_t *ctr, uint32_t blk_nbr, uint8_t *ct,
    sbdi_tag_t tag)
{
  // if the context is non-null then this is used incorrectly
  assert(!ctx);
  SBDI_CHK_PARAM(pt && ctr && pt_len > 0 && tag);
  memset(tag, 0xFF, SBDI_BLOCK_TAG_SIZE);
  if (pt == ct) {
    return SBDI_SUCCESS;
  }
  memcpy(ct, pt, pt_len);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_nocrypto_decrypt(void *ctx, const uint8_t *ct,
    const int ct_len, const sbdi_ctr_pkd_t ctr, const uint32_t blk_nbr,
    uint8_t *pt, const sbdi_tag_t tag)
{
  // if the context is non-null then this is used incorrectly
  assert(!ctx);
  SBDI_CHK_PARAM(
      ct && ct_len > 0 && ctr && sbdi_block_is_valid_phy(blk_nbr) && pt && tag);
  if (pt == ct) {
    return SBDI_SUCCESS;
  }
  memcpy(pt, ct, ct_len);
  int i;
  // sanity check
  for (i = 0; i < SBDI_BLOCK_TAG_SIZE; ++i) {
    if (tag[i] != 0) {
      return SBDI_ERR_TAG_MISMATCH;
    }
  }
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_nocrypto_mac(void *ctx, const unsigned char *msg,
    const int mlen, unsigned char *C, const unsigned char *ad, const int ad_len)
{
  // if their is a context, then something is wrong
  assert(!ctx);
  SBDI_CHK_PARAM(msg && mlen > 0 && C);
  memset(C, 0x00, SBDI_BLOCK_TAG_SIZE);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_nocrypto_create(sbdi_crypto_t **crypto, const sbdi_key_t key)
{
  sbdi_crypto_t *c = calloc(1, sizeof(sbdi_crypto_t));
  if (!c) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  c->enc = &sbdi_nocrypto_encrypt;
  c->dec = &sbdi_nocrypto_decrypt;
  c->mac = &sbdi_nocrypto_mac;
  *crypto = c;
  return SBDI_SUCCESS;
}

void sbdi_nocrypto_destroy(sbdi_crypto_t *crypto)
{
  free(crypto);
}

