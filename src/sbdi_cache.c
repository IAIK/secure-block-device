/*
 * sbdi_cache.c
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#include "sbdi_cache.h"

#include <stdlib.h>
#include <string.h>
#ifdef SBDI_CACHE_PROFILE
#include <stdio.h>
#include <inttypes.h>
#endif

#define SBDI_BC_ERR_CHK(f) do {sbdi_error_t r = f;if (r != SBDI_SUCCESS) {return r;}} while (0)

#define  IDX_P1(IDX) ((IDX+1) % SBDI_CACHE_MAX_SIZE)
#define  IDX_S1(IDX) ((IDX-1) % SBDI_CACHE_MAX_SIZE)
#define INC_IDX(IDX) do {IDX = IDX_P1(IDX);} while (0)
#define DEC_IDX(IDX) do {IDX = IDX_S1(IDX);} while (0)
#define SWAP(X, Y) do {(X) = (X) ^ (Y); (Y) = (X) ^ (Y); (X) = (X) ^ (Y);} while (0)

//----------------------------------------------------------------------
sbdi_bc_t *sbdi_bc_cache_create(sbdi_sync_fp_t sync, void *sync_data)
{
  if (!sync || !sync_data) {
    return NULL;
  }
  sbdi_bc_t *cache = calloc(1, sizeof(sbdi_bc_t));
  if (!cache) {
    return NULL;
  }
  // set sync callback
  cache->sync = sync;
  cache->sync_data = sync_data;
  // Initialize lru (Superfluous under calloc)
  cache->index.lru = 0;
  // Initialize block cache index numbers
  for (uint32_t i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    // set block index to invalid
    cache->index.list[i].block_idx = UINT32_MAX;
    // set cache index
    cache->index.list[i].cache_idx = i;
    // clear flags (Superfluous under calloc)
    cache->index.list[i].flags = 0;
  }
  return cache;
}

//----------------------------------------------------------------------
void sbdi_bc_cache_destroy(sbdi_bc_t *cache)
{
  free(cache);
}

//----------------------------------------------------------------------
static inline sbdi_error_t sbdi_bc_swap(sbdi_bc_idx_t *idx, uint32_t idx_1,
    uint32_t idx_2)
{
  if (!idx || idx_1 > SBDI_CACHE_MAX_SIZE || idx_2 > SBDI_CACHE_MAX_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  SWAP(idx->list[idx_1].block_idx, idx->list[idx_2].block_idx);
  SWAP(idx->list[idx_1].cache_idx, idx->list[idx_2].cache_idx);
  SWAP(idx->list[idx_1].flags, idx->list[idx_2].flags);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bc_find_blk(sbdi_bc_t *cache, sbdi_block_t *blk)
{
  if (!cache || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  uint32_t cdt = idx->lru;
  do {
    DEC_IDX(cdt);
    if (idx->list[cdt].block_idx == blk->idx) {
      if (IDX_P1(cdt) == idx->lru) {
        blk->data = cache->store + idx->list[cdt].cache_idx;
#ifdef SBDI_CACHE_PROFILE
        cache->hits++;
#endif
        return SBDI_SUCCESS;
      } else {
        SBDI_BC_ERR_CHK(sbdi_bc_swap(idx, cdt, IDX_P1(cdt)));
        blk->data = cache->store + idx->list[IDX_P1(cdt)].cache_idx;
#ifdef SBDI_CACHE_PROFILE
        cache->hits++;
#endif
        return SBDI_SUCCESS;
      }
    }
  } while (cdt != idx->lru);
  blk->data = NULL;
#ifdef SBDI_CACHE_PROFILE
  cache->misses++;
#endif
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_bc_cache_blk(sbdi_bc_t *cache, sbdi_block_t *blk,
    sbdi_bc_bt_t blk_type)
{
  if (!cache || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX
      || blk_type == SBDI_BC_BT_RESV) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  blk->data = NULL;
  SBDI_BC_ERR_CHK(sbdi_bc_find_blk(cache, blk));
  if (blk->data) {
    return SBDI_SUCCESS;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  // Make sure the block that gets evicted is in sync!
  sbdi_block_t to_sync;
  if (sbdi_bc_is_valid_and_dirty(&idx->list[idx->lru])) {
    if (sbdi_bc_is_mngt_blk(idx->list[idx->lru].flags)) {
      // in case we deal with a management block it is probably best to
      // sync out all blocks. This SHOULD ensure a consistent state.
      SBDI_BC_ERR_CHK(sbdi_bc_sync(cache));
    } else {
      sbdi_block_init(&to_sync, idx->list[idx->lru].block_idx,
          cache->store + idx->list[idx->lru].cache_idx);
      SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
      sbdi_bc_clear_blk_dirty(&idx->list[idx->lru]);
    }
  }
  idx->list[idx->lru].block_idx = blk->idx;
  sbdi_bc_set_blk_type(&idx->list[idx->lru], blk_type);
  blk->data = cache->store + idx->list[idx->lru].cache_idx;
  INC_IDX(idx->lru);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_bc_dirty_blk(sbdi_bc_t *cache, sbdi_block_t *blk)
{
  if (!cache || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  uint32_t cdt = idx->lru;
  do {
    DEC_IDX(cdt);
    if (idx->list[cdt].block_idx == blk->idx) {
      sbdi_bc_set_blk_dirty(&idx->list[cdt]);
      return SBDI_SUCCESS;
    }
  } while (cdt != idx->lru);
  return SBDI_ERR_ILLEGAL_STATE;
}

sbdi_error_t sbdi_bc_evict_blk(sbdi_bc_t *cache, sbdi_block_t *blk)
{
  if (!cache || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  uint32_t cdt = idx->lru;
  do {
    DEC_IDX(cdt);
    if (idx->list[cdt].block_idx == blk->idx) {
      idx->list[cdt].block_idx = UINT32_MAX;
      if (cdt == idx->lru) {
        return SBDI_SUCCESS;
      } else {
        // need to find out if there are any valid blocks between lru and
        // cdt. If so swap with the closest to LRU.
        uint32_t swp = idx->lru;
        while (swp != cdt) {
          if (sbdi_bc_is_valid(idx->list[swp].block_idx)) {
            SBDI_BC_ERR_CHK(sbdi_bc_swap(idx, cdt, swp));
          }
          INC_IDX(swp);
        }
        return SBDI_SUCCESS;
      }
    }
  } while (cdt != idx->lru);
  // Block marked for eviction not found, this is bad news, as the only
  // place where this function is called, is when a cache reservation
  // must be invalidated, because a block could not be loaded. This means
  // the block to be evicted must be in cache at this point.
  return SBDI_ERR_ILLEGAL_STATE;
}

sbdi_error_t sbdi_bc_sync(sbdi_bc_t *cache)
{
  if (!cache) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_block_t to_sync;
  sbdi_bc_idx_t *idx = &cache->index;
  // Sync out data blocks first and then the corresponding management
  // blocks
  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    if (sbdi_bc_is_valid_and_dirty(&idx->list[i])
        && !sbdi_bc_is_mngt_blk(idx->list[i].flags)) {
      // Not a management block, but dirty ==> sync in the first round
      sbdi_block_init(&to_sync, idx->list[i].block_idx,
          cache->store + idx->list[i].cache_idx);
      SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
      sbdi_bc_clear_blk_dirty(&idx->list[i]);
    }
  }
  // Second round: sync out all remaining dirty management blocks
  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    if (sbdi_bc_is_valid_and_dirty(&idx->list[i])) {
      sbdi_block_init(&to_sync, idx->list[i].block_idx,
          cache->store + idx->list[i].cache_idx);
      SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
      sbdi_bc_clear_blk_dirty(&idx->list[i]);
    }
  }
  return SBDI_SUCCESS;
}

#ifdef SBDI_CACHE_PROFILE
void sbdi_bc_print_stats(sbdi_bc_t *cache)
{
  printf("%" PRIu64 " hits/%" PRIu64 " misses; ratio: %f\n", cache->hits,
      cache->misses, (double) cache->hits / (double) cache->misses);
}
#endif
