/*
 * secblock.c
 *
 *  Created on: May 13, 2014
 *      Author: dhein
 */

#include "siv.h"

#include "SecureBlockDeviceInterface.h"

#include <string.h>

static inline void sbdi_init(sbdi_t *sbdi, sbdi_pio_t *pio, siv_ctx *ctx,
    mt_t *mt, sbdi_bc_t *cache)
{
  assert(sbdi && ctx && mt && cache);
  memset(sbdi, 0, sizeof(sbdi_t));
  sbdi->pio = pio;
  sbdi->ctx = ctx;
  sbdi->mt = mt;
  sbdi->cache = cache;
  sbdi->write_store[0].data = &sbdi->write_store_dat[0];
  sbdi->write_store[1].data = &sbdi->write_store_dat[1];
}

//----------------------------------------------------------------------
sbdi_t *sbdi_create(sbdi_pio_t *pio)
{
  sbdi_t *sbdi = malloc(sizeof(sbdi_t));
  if (!sbdi) {
    return NULL;
  }
  memset(sbdi, 0, sizeof(sbdi_t));
  siv_ctx *ctx = malloc(sizeof(siv_ctx));
  if (!ctx) {
    free(sbdi);
    return NULL;
  }
  memset(ctx, 0, sizeof(siv_ctx));
  mt_t *mt = mt_create();
  if (!mt) {
    free(ctx);
    free(sbdi);
    return NULL;
  }
  sbdi_bc_t *cache = sbdi_bc_cache_create(&sbdi_bl_sync, sbdi);
  if (!cache) {
    mt_delete(mt);
    free(ctx);
    free(sbdi);
    return NULL;
  }
  sbdi_init(sbdi, pio, ctx, mt, cache);
  return sbdi;
}

//----------------------------------------------------------------------
void sbdi_delete(sbdi_t *sbdi)
{
  if (!sbdi) {
    return;
  }
  sbdi_bc_cache_destroy(sbdi->cache);
  mt_delete(sbdi->mt);
  // Overwrite key material
  memset(sbdi->ctx, 0, sizeof(siv_ctx));
  free(sbdi->ctx);
  // Overwrite header if present
  sbdi_hdr_v1_delete(sbdi->hdr);
  memset(sbdi, 0, sizeof(sbdi_t));
  free(sbdi);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_open(sbdi_t **s, sbdi_pio_t *pio, sbdi_sym_mst_key_t mkey,
    mt_hash_t root)
{
  // TODO what about root? Can be null, but only ...
  SBDI_CHK_PARAM(s && pio && mkey);
  // variables that need explicit cleaning
  siv_ctx mctx;
  memset(&mctx, 0, sizeof(siv_ctx));
  sbdi_hdr_v1_sym_key_t key;
  memset(&key, 0, sizeof(sbdi_hdr_v1_sym_key_t));
  sbdi_error_t r = SBDI_ERR_UNSPECIFIED;
  // Start body of function
  int cr = siv_init(&mctx, mkey, SIV_256);
  if (cr == -1) {
    r = SBDI_ERR_CRYPTO_FAIL;
    goto FAIL;
  }
  sbdi_t *sbdi = sbdi_create(pio);
  r = sbdi_hdr_v1_read(sbdi, &mctx);
  if (r == SBDI_ERR_IO_MISSING_BLOCK) {
    // Empty block device ==> create header
    // TODO find a better way to provide nonce material
    const char *n1 = "nonce1";
    const char *n2 = "nonce2";
    sbdi_hdr_v1_derive_key(&mctx, key, (uint8_t*) n1, strlen(n1), (uint8_t*) n2,
        strlen(n2));
    cr = siv_init(sbdi->ctx, key, SIV_256);
    if (cr == -1) {
      r = SBDI_ERR_CRYPTO_FAIL;
      goto FAIL;
    }
    r = sbdi_hdr_v1_create(&sbdi->hdr, key);
    if (r != SBDI_SUCCESS) {
      goto FAIL;
    }
    r = sbdi_hdr_v1_write(sbdi, &mctx);
    if (r != SBDI_SUCCESS) {
      // TODO this is really bad and needs good error handling
      goto FAIL;
    }
    *s = sbdi;
    return SBDI_SUCCESS;
  } else if (r != SBDI_SUCCESS) {
    goto FAIL;
  }
  // Header read init sbdi key context
  cr = siv_init(sbdi->ctx, sbdi->hdr->key, SIV_256);
  if (cr == -1) {
    r = SBDI_ERR_CRYPTO_FAIL;
    goto FAIL;
  }
  sbdi_bl_verify_block_layer(sbdi, root, pio->size_at_open / SBDI_BLOCK_SIZE);
  *s = sbdi;
  return SBDI_SUCCESS;

  FAIL: memset(&mctx, 0, sizeof(siv_ctx));
  memset(key, 0, sizeof(sbdi_hdr_v1_sym_key_t));
  sbdi_delete(sbdi);
  return r;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_close(sbdi_t *sbdi, sbdi_sym_mst_key_t mkey, mt_hash_t root)
{
  SBDI_CHK_PARAM(sbdi && mkey && root);
  siv_ctx mctx;
  memset(&mctx, 0, sizeof(siv_ctx));
  sbdi_error_t r = SBDI_ERR_UNSPECIFIED;
  int cr = siv_init(&mctx, mkey, SIV_256);
  if (cr == -1) {
    r = SBDI_ERR_CRYPTO_FAIL;
    goto FAIL;
  }
  r = sbdi_hdr_v1_write(sbdi, &mctx);
  if (r != SBDI_SUCCESS) {
    // TODO very bad, potentially partially written header!
    goto FAIL;
  }
  r = sbdi_bc_sync(sbdi->cache);
  if (r != SBDI_SUCCESS) {
    // TODO very bad, potentially inconsistent state!
    goto FAIL;
  }
  // TODO convert error and return
  r = sbdi_mt_sbdi_err_conv(mt_get_root(sbdi->mt, root));
  if (r != SBDI_SUCCESS) {
    // this should not happen, because it should have failed earlier
    goto FAIL;
  }
  sbdi_delete(sbdi);
  return SBDI_SUCCESS;

  FAIL: memset(&mctx, 0, sizeof(siv_ctx));
  return r;
}
