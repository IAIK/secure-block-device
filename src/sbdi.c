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
sbdi_t *sbdi_create(sbdi_pio_t *pio, uint8_t *key, size_t key_len)
{
  sbdi_t *sbdi = malloc(sizeof(sbdi_t));
  if (!sbdi) {
    return NULL;
  }
  siv_ctx *ctx = malloc(sizeof(siv_ctx));
  if (!ctx) {
    free(sbdi);
    return NULL;
  }
  int cr = siv_init(ctx, key, key_len);
  if (cr == -1) {
    free(ctx);
    free(sbdi);
    return NULL;
  }

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
  sbdi_bc_cache_destroy(sbdi->cache);
  mt_delete(sbdi->mt);
  free(sbdi->ctx);
  free(sbdi);
}

//----------------------------------------------------------------------
sbdi_t *sbdi_open(sbdi_pio_t *pio, sbdi_sym_mst_key_t mkey)
{
  sbdi_create(pio, mkey, sizeof(sbdi_sym_mst_key_t));
  return 0;
}

//----------------------------------------------------------------------
void sbdi_close(sbdi_t *sbdi) {
  sbdi_delete(sbdi);
}
