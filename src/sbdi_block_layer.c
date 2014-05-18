/*
 * sbdi_block_layer.c
 *
 *  Created on: May 17, 2014
 *      Author: dhein
 */

#include "merkletree.h"
#include "siv.h"

#include "sbdi_config.h"
#include "sbdi_cache.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef struct secure_block_device_interface {
  int fd;
  siv_ctx *ctx;
  sbdi_bc_t *cache;
  mt_t *mt;
} sbdi_t;

typedef uint8_t sbdi_tag_t[SBDI_BLOCK_TAG_SIZE];

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len)
{
  if (!sbdi || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ssize_t r = pread(sbdi->fd, blk->data, len, blk->idx * SBDI_BLOCK_SIZE);
  if (r == -1) {
    return SBDI_ERR_IO;
  } else if (r < len) {
    return SBDI_ERR_MISSING_DATA;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_cache_decrypt(sbdi_t *sbdi, sbdi_block_t *blk, size_t len,
    sbdi_tag_t *tag, unsigned char *blk_ctr, int ctr_len)
{
  if (!sbdi || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX || len == 0
      || len > SBDI_BLOCK_SIZE || !tag
      || (blk_ctr && ctr_len != SBDI_BLOCK_ACCESS_COUNTER_SIZE)) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_error_t r = sbdi_bc_cache_blk(sbdi->cache, blk);
  if (r != SBDI_SUCCESS) {
    return r;
  } else if (!blk->data) {
    return SBDI_ERR_ILLEGAL_STATE;
  }
  r = sbdi_bl_read_block(sbdi, blk, len);
  if (r != SBDI_SUCCESS) {
    // TODO free block reservation in cache!
    return r;
  }
  siv_restart(sbdi->ctx);
  int cr = -1;
  if (blk_ctr == NULL) {
    cr = siv_decrypt(sbdi->ctx, blk->data[0], blk->data[0], SBDI_BLOCK_SIZE,
        *tag, 1, &blk->idx, sizeof(uint32_t));
  } else {
    cr = siv_decrypt(sbdi->ctx, blk->data[0], blk->data[0], SBDI_BLOCK_SIZE,
        *tag, 2, &blk->idx, sizeof(uint32_t), blk_ctr, ctr_len);
  }
  if (cr == -1) {
    // TODO free block reservation in cache!
    return SBDI_ERR_CRYPTO_FAIL;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_read_data_block(sbdi_t *sbdi, unsigned int *ptr,
    uint32_t idx, size_t len)
{
  if (!sbdi || !ptr || idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE) {
    // TODO Question Johannes about 'deep' error checking (internal struct state)
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  // TODO check that read is not beyond the bounds of file, otherwise the
  // Merkle tree won't work correctly!
  uint32_t mng_nbr = idx / SBDI_MNGT_BLOCK_ENTRIES;
  uint32_t mng_idx = mng_nbr * SBDI_MNGT_BLOCK_ENTRIES;
  uint32_t dat_idx = idx + mng_nbr + 2;
  uint32_t tag_idx = idx % SBDI_MNGT_BLOCK_ENTRIES;

  sbdi_error_t r;
  sbdi_block_t mng_dat, blk_dat;
  sbdi_block_t *mngt = &mng_dat;
  sbdi_block_t *blk = &blk_dat;
  sbdi_block_init(mngt, mng_idx, NULL);
  sbdi_block_init(blk, dat_idx, NULL);
  r = sbdi_bc_find_blk(sbdi->cache, mngt);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  if (!mngt->data) {
//    // Block not yet in cache
    sbdi_tag_t mng_tag;
    r = sbdi_bl_cache_decrypt(sbdi, mngt, len, &mng_tag, NULL, 0);
    if (r != SBDI_SUCCESS) {
      // TODO Cleanup?
      return r;
    }
//    r = sbdi_bc_cache_blk(sbdi->cache, mng_idx, &mngt);
//    if (r != SBDI_SUCCESS) {
//      return r;
//    } else if (!mngt) {
//      return SBDI_ERR_ILLEGAL_STATE;
//    }
//    r = sbdi_bl_read_block(sbdi, *mngt, mng_idx, SBDI_BLOCK_SIZE);
//    if (r != SBDI_SUCCESS) {
//      // TODO free block reservation in cache!
//      return r;
//    }
//    // Add block index as additional information to the decryption
//    if (!siv_decrypt(sbdi->ctx, *mngt, *mngt, SBDI_BLOCK_SIZE, mng_tag, 1,
//        &mng_idx, sizeof(uint32_t))) {
//      // TODO free block reservation in cache!
//      return SBDI_ERR_CRYPTO_FAIL;
//    }
    // TODO add management tag to Merkle tree and validate root
    mt_error_t mt_r;
    mt_r = mt_verify(sbdi->mt, NULL, mng_nbr);
    if (mt_r != MT_SUCCESS) {
      // TODO better error code mapping?
      return SBDI_ERR_TAG_MISMATCH;
    }
  }
  r = sbdi_bc_find_blk(sbdi->cache, blk);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  unsigned char *blk_ctr = mngt->data[tag_idx + SBDI_BLOCK_TAG_SIZE];
  if (!(blk->data)) {
    sbdi_tag_t tag;
    r = sbdi_bl_cache_decrypt(sbdi, blk, SBDI_BLOCK_SIZE, &tag, blk_ctr,
        SBDI_BLOCK_ACCESS_COUNTER_SIZE);
    if (r != SBDI_SUCCESS) {
      // TODO Cleanup?
      return r;
    }
    if (!memcmp(tag, &mngt[tag_idx], SBDI_BLOCK_TAG_SIZE)) {
      return SBDI_ERR_TAG_MISMATCH;
    }
  }
  // Copy data block from cache into target buffer
  memcpy(ptr, blk->data, len);
  return SBDI_SUCCESS;
}

