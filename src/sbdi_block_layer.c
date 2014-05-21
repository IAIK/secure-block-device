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

#define SBDI_CACHE_SIZE ((SBDI_CACHE_MAX_SIZE)  * (SBDI_BLOCK_SIZE))

typedef struct secure_block_device_interface {
  int fd;
  siv_ctx *ctx;
  sbdi_bc_t *cache;
  mt_t *mt;
  sbdi_db_t write_store;
  sbdi_ctr_128b_t g_ctr;
} sbdi_t;

typedef uint8_t sbdi_tag_t[SBDI_BLOCK_TAG_SIZE];

//----------------------------------------------------------------------
sbdi_error_t sbdi_block_pair_init(sbdi_block_pair_t *pair, uint32_t mng_nbr,
    uint32_t mng_idx, uint32_t dat_idx, uint32_t tag_idx)
{
  if (!pair) {
    // TODO Additional error handling?
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  pair->mng_nbr = mng_nbr;
  pair->tag_idx = tag_idx;
  pair->mng = &pair->mng_dat;
  pair->blk = &pair->blk_dat;
  sbdi_block_init(pair->mng, mng_idx, NULL);
  sbdi_block_init(pair->blk, dat_idx, NULL);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len)
{
  if (!sbdi || !blk || !blk->data || blk->idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE || blk->data < sbdi->cache->store
      || blk->data > sbdi->cache->store + SBDI_CACHE_SIZE) {
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
  sbdi_bc_bt_t blk_type = (blk_ctr == NULL) ? SBDI_BC_BT_MNGT : SBDI_BC_BT_DATA;
  sbdi_error_t r = sbdi_bc_cache_blk(sbdi->cache, blk, blk_type);
  if (r != SBDI_SUCCESS) {
    return r;
  } else if (!blk->data) {
    return SBDI_ERR_ILLEGAL_STATE;
  }
  r = sbdi_bl_read_block(sbdi, blk, len);
  if (r != SBDI_SUCCESS) {
    sbdi_bc_evict_blk(sbdi->cache, blk);
    return r;
  }
  siv_restart(sbdi->ctx);
  int cr = -1;
  if (blk_ctr == NULL) {
    // Add block index as additional information to the decryption
    cr = siv_decrypt(sbdi->ctx, blk->data[0], blk->data[0], SBDI_BLOCK_SIZE,
        *tag, 1, &blk->idx, sizeof(uint32_t));
  } else {
    // Add block index and block counter as additional information to the decryption
    cr = siv_decrypt(sbdi->ctx, blk->data[0], blk->data[0], SBDI_BLOCK_SIZE,
        *tag, 2, &blk->idx, sizeof(uint32_t), blk_ctr, ctr_len);
  }
  if (cr == -1) {
    sbdi_bc_evict_blk(sbdi->cache, blk);
    return SBDI_ERR_CRYPTO_FAIL;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
static inline uint32_t sbdi_get_mngt_block_number(uint32_t idx)
{
  return idx / SBDI_MNGT_BLOCK_ENTRIES;
}

//----------------------------------------------------------------------
static inline uint32_t sbdi_get_mngt_block_index(uint32_t idx)
{
  return (sbdi_get_mngt_block_number(idx) * SBDI_MNGT_BLOCK_ENTRIES)
      + sbdi_get_mngt_block_number(idx) + 1;
}

//----------------------------------------------------------------------
static inline uint32_t sbdi_get_data_block_index(uint32_t idx)
{
  return idx + sbdi_get_mngt_block_number(idx) + 2;
}

//----------------------------------------------------------------------
static inline uint32_t sbdi_get_mngt_tag_index(uint32_t idx)
{
  return idx % SBDI_MNGT_BLOCK_ENTRIES;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_data_block_i(sbdi_t *sbdi, sbdi_block_pair_t *pair)
{
  sbdi_error_t r = sbdi_bc_find_blk(sbdi->cache, pair->mng);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  if (!pair->mng->data) {
    // Block not yet in cache
    sbdi_tag_t mng_tag;
    r = sbdi_bl_cache_decrypt(sbdi, pair->mng, SBDI_BLOCK_SIZE, &mng_tag, NULL,
        0);
    if (r != SBDI_SUCCESS) {
      // TODO Cleanup?
      return r;
    }
    // TODO add management tag to Merkle tree and validate root
    mt_error_t mt_r;
    mt_r = mt_verify(sbdi->mt, NULL, pair->mng_nbr);
    if (mt_r != MT_SUCCESS) {
      // TODO better error code mapping?
      return SBDI_ERR_TAG_MISMATCH;
    }
  }
  r = sbdi_bc_find_blk(sbdi->cache, pair->blk);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  unsigned char *blk_ctr = pair->mng->data[pair->tag_idx + SBDI_BLOCK_TAG_SIZE];
  if (!(pair->blk->data)) {
    sbdi_tag_t tag;
    r = sbdi_bl_cache_decrypt(sbdi, pair->blk, SBDI_BLOCK_SIZE, &tag, blk_ctr,
    SBDI_BLOCK_ACCESS_COUNTER_SIZE);
    if (r != SBDI_SUCCESS) {
      // TODO Cleanup?
      return r;
    }
    if (!memcmp(tag, &pair->mng[pair->tag_idx], SBDI_BLOCK_TAG_SIZE)) {
      return SBDI_ERR_TAG_MISMATCH;
    }
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t len)
{
  if (!sbdi || !ptr || idx > SBDI_BLOCK_MAX_INDEX || len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  // TODO check that read is not beyond the bounds of file, otherwise the
  // Merkle tree won't work correctly!
  uint32_t mng_nbr = sbdi_get_mngt_block_number(idx);
  uint32_t mng_idx = sbdi_get_mngt_block_index(idx);
  uint32_t dat_idx = sbdi_get_data_block_index(idx);
  uint32_t tag_idx = sbdi_get_mngt_tag_index(idx);
  sbdi_block_pair_t pair;
  sbdi_block_pair_init(&pair, mng_nbr, mng_idx, dat_idx, tag_idx);
  sbdi_error_t r = sbdi_bl_read_data_block_i(sbdi, &pair);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  // Copy data block from cache into target buffer
  memcpy(ptr, pair.blk->data, len);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_write_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len)
{
  if (!sbdi || !blk || !blk->data || blk->idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE || blk->data < sbdi->cache->store
      || blk->data > sbdi->cache->store + SBDI_CACHE_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ssize_t r = pwrite(sbdi->fd, blk->data, len, blk->idx * SBDI_BLOCK_SIZE);
  if (r == -1) {
    return SBDI_ERR_IO;
  } else if (r < len) {
    return SBDI_ERR_MISSING_DATA;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_write_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t len)
{
  if (!sbdi || !ptr || idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  // TODO check that read is not beyond the bounds of file, otherwise the
  // Merkle tree won't work correctly!
  // TODO Think about caching behavior, when only one of the pair is in cache and is also the LRU.
  uint32_t mng_nbr = sbdi_get_mngt_block_number(idx);
  uint32_t mng_idx = sbdi_get_mngt_block_index(idx);
  uint32_t dat_idx = sbdi_get_data_block_index(idx);
  uint32_t tag_idx = sbdi_get_mngt_tag_index(idx);
  sbdi_block_pair_t pair;
  sbdi_error_t r = sbdi_block_pair_init(&pair, mng_nbr, mng_idx, dat_idx,
      tag_idx);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  r = sbdi_bl_read_data_block_i(sbdi, &pair);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  memcpy(pair.blk->data, ptr, len);
  // Nothing has of yet been written to the management block. This has to be
  // done by the sync function, when the dependent data blocks are synced.
  // Afterwards the management block should be written.
  r = sbdi_bc_dirty_blk(sbdi->cache, pair.mng);
  return sbdi_bc_dirty_blk(sbdi->cache, pair.blk);
  //sbdi_error_t r;
  // Make sure block is in cache
  // What I need to do:
  // * Read Block into cache (done)
  // * Get block access counter
  // * Increment block access counter
  // * Write to cache
  // * Cache is synced later on
  // * Write back new block access counter and tag to management block (also in cache)
  //
}

//----------------------------------------------------------------------
static sbdi_error_t sbdi_bl_sync_i(sbdi_t *sbdi, sbdi_block_t *blk)
{
  if (!sbdi || !blk || !blk->data || blk->idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_idx_elem_t *idx_list = sbdi->cache->index.list;
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(sbdi->cache, blk->idx);
  if (idx_pos >= SBDI_BLOCK_MAX_INDEX
      || !sbdi_bc_is_blk_dirty(idx_list[idx_pos].flags)) {
    return SBDI_ERR_ILLEGAL_STATE;
  }
  int cr = -1;
  sbdi_tag_t tag;
  switch (sbdi_bc_get_blk_type(idx_list[idx_pos].flags)) {
  case SBDI_BC_BT_MNGT:
    // Add block index as additional information to the decryption
    cr = siv_decrypt(sbdi->ctx, blk->data[0], blk->data[0], SBDI_BLOCK_SIZE,
        *tag, 1, &blk->idx, sizeof(uint32_t));
    break;
  case SBDI_BC_BT_DATA:
    // TODO can the same context be used for en- and decryption?
    // encrypt block into write store using physical block index and the
    // global counter as additional headers
    cr = siv_encrypt(sbdi->ctx, blk->data[0], sbdi->write_store, SBDI_BLOCK_SIZE,
        tag, 2, &blk->idx, sizeof(uint32_t), &sbdi->g_ctr, sizeof(sbdi_ctr_128b_t));
    if (cr == -1) {
      return SBDI_ERR_CRYPTO_FAIL;
    }
    break;
  default:
    return SBDI_ERR_ILLEGAL_STATE;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_sync(void *sbdi, sbdi_block_t *blk)
{
  return sbdi_bl_sync_i((sbdi_t *) sbdi, blk);
}
