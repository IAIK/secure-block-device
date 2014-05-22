/*
 * sbdi_cache.c
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#include "sbdi_cache.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifdef SBDI_CACHE_PROFILE
#include <stdio.h>
#include <inttypes.h>
#endif

#define SBDI_BC_ERR_CHK(f) do {sbdi_error_t r = f;if (r != SBDI_SUCCESS) {return r;}} while (0)
#define SBDI_BC_CHK_IDX_POS(cache_idx) do {if (!sbdi_bc_idx_is_valid(cache_idx)) {return SBDI_ERR_ILLEGAL_STATE;}} while (0)

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

/*!
 * \brief Gets the index of the cache
 *
 * The cache index contains information which cache storage cell contains
 * data from which physical block index and the block flags.
 *
 * @param cache the cache data type instance to get the index from
 * @return the cache index
 */
static inline sbdi_bc_idx_t *bc_get_idx(sbdi_bc_t *cache)
{
  assert(cache);
  return &cache->index;
}

/*!
 * \brief Swaps to elements in the block cache index
 * @param idx the block cache index type instance
 * @param idx_1 the index of the first element to swap in the block cache
 * index
 * @param idx_2 the index of the second element to swap in the block cache
 * index
 * @return SBDI_SUCCESS if the swap is successful, SBDI_ERR_ILLEGAL_PARAM if
 * one of the given parameters is invalid
 */
static inline sbdi_error_t sbdi_bc_swap(sbdi_bc_t *cache, uint32_t idx_1,
    uint32_t idx_2)
{
  if (!cache || idx_1 > SBDI_CACHE_MAX_SIZE || idx_2 > SBDI_CACHE_MAX_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_idx_t *idx = bc_get_idx(cache);
  SWAP(idx->list[idx_1].block_idx, idx->list[idx_2].block_idx);
  SWAP(idx->list[idx_1].cache_idx, idx->list[idx_2].cache_idx);
  SWAP(idx->list[idx_1].flags, idx->list[idx_2].flags);
  return SBDI_SUCCESS;
}

static inline uint32_t idx_get_lru(sbdi_bc_t *cache)
{
  assert(cache);
  assert(cache->index.lru < SBDI_CACHE_MAX_SIZE);
  return cache->index.lru;
}

static inline void idx_inc_lru(sbdi_bc_t *cache)
{
  assert(cache);
  SBDI_BC_INC_IDX(cache->index.lru);
  assert(cache->index.lru < SBDI_CACHE_MAX_SIZE);
}

static inline uint32_t idx_get_cache_idx(sbdi_bc_t *cache, uint32_t idx)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE);
  assert(cache->index.list[idx].cache_idx < SBDI_CACHE_MAX_SIZE);
  return cache->index.list[idx].cache_idx;
}

static inline void idx_set_cache_idx(sbdi_bc_t *cache, uint32_t idx,
    uint32_t val)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE && val < SBDI_CACHE_MAX_SIZE);
  cache->index.list[idx].cache_idx = val;
}

static inline uint32_t idx_get_phy_idx(sbdi_bc_t *cache, uint32_t idx)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE);
  assert(cache->index.list[idx].block_idx < SBDI_BLOCK_MAX_INDEX);
  return cache->index.list[idx].block_idx;
}

static inline void idx_set_phy_idx(sbdi_bc_t *cache, uint32_t idx,
    uint32_t val)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE && val < SBDI_BLOCK_MAX_INDEX);
  cache->index.list[idx].block_idx = val;
}

static inline void idx_invalidate_phy_idx(sbdi_bc_t *cache, uint32_t idx)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE);
  cache->index.list[idx].block_idx = UINT32_MAX;
}

static inline sbdi_db_t *sbdi_bc_get_db_for_cache_idx(sbdi_bc_t *cache,
    uint32_t idx)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE);
  return sbdi_bc_get_db_address(cache, idx_get_cache_idx(cache, idx));
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bc_find_blk(sbdi_bc_t *cache, sbdi_block_t *blk)
{
  if (!cache || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(cache, blk->idx);
  if (idx_pos >= SBDI_CACHE_MAX_SIZE) {
    blk->data = NULL;
#ifdef SBDI_CACHE_PROFILE
    cache->misses++;
#endif
    return SBDI_SUCCESS;
  }
  if (SBDI_BC_IDX_P1(idx_pos) == idx_get_lru(cache)) {
    blk->data = sbdi_bc_get_db_for_cache_idx(cache, idx_pos);
#ifdef SBDI_CACHE_PROFILE
    cache->hits++;
#endif
    return SBDI_SUCCESS;
  } else {
    SBDI_BC_ERR_CHK(sbdi_bc_swap(cache, idx_pos, SBDI_BC_IDX_P1(idx_pos)));
    blk->data = sbdi_bc_get_db_for_cache_idx(cache, SBDI_BC_IDX_P1(idx_pos));
#ifdef SBDI_CACHE_PROFILE
    cache->hits++;
#endif
    return SBDI_SUCCESS;
  }
}

/*!
 *\brief Syncs all data blocks belonging to a specific management block
 * @param cache the cache data type
 * @param mng_idx the cache list index of the cache index element describing
 * the management block
 * @return SBDI_SUCCESS if the operation succeeds, SBDI_ERR_ILLEGAL_PARAM if
 * any of the given parameters is invalid
 */
static sbdi_error_t sbdi_bc_sync_mngt_blk(sbdi_bc_t *cache, uint32_t mng_idx)
{
  if (!cache || mng_idx > SBDI_CACHE_MAX_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_block_t to_sync;
  sbdi_bc_idx_t *idx = &cache->index;
  uint32_t mng_phy_idx = idx->list[mng_idx].block_idx;
  // Sync out data blocks first and then the corresponding management block
  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    if (sbdi_bc_is_valid_and_dirty(cache, i)
        && !sbdi_bc_is_mngt_blk(cache, i)
        && sbdi_bc_is_in_mngt_scope(mng_phy_idx, idx->list[i].block_idx)) {
      // Not a management block, but dirty and in scope of the management
      // block ==> sync
      sbdi_block_init(&to_sync, idx->list[i].block_idx,
          sbdi_bc_get_db_address(cache, idx->list[i].cache_idx));
      SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
      sbdi_bc_clear_blk_dirty(cache, i);
    }
  }
  // Now sync out the corresponding management block
  sbdi_block_init(&to_sync, idx->list[mng_idx].block_idx,
      sbdi_bc_get_db_address(cache, idx->list[mng_idx].cache_idx));
  SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
  sbdi_bc_clear_blk_dirty(cache, mng_idx);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
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
  // Make sure the block that gets evicted is in sync!
  sbdi_block_t to_sync;
  if (sbdi_bc_is_valid_and_dirty(cache, idx_get_lru(cache))) {
    if (sbdi_bc_is_mngt_blk(cache, idx_get_lru(cache))) {
      // in case we deal with a management block it is probably best to
      // sync out all its dependent blocks. This SHOULD ensure a consistent
      // state.
      SBDI_BC_ERR_CHK(sbdi_bc_sync_mngt_blk(cache, idx_get_lru(cache)));
    } else {
      // This is just a data block, sync it out
      sbdi_block_init(&to_sync, idx_get_phy_idx(cache, idx_get_lru(cache)),
          sbdi_bc_get_db_for_cache_idx(cache, idx_get_lru(cache)));
      SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
      sbdi_bc_clear_blk_dirty(cache, idx_get_lru(cache));
    }
  }
  // Finally, reserve the cache entry for the new block
  idx_set_phy_idx(cache, idx_get_lru(cache), blk->idx);
  sbdi_bc_set_blk_type(cache, idx_get_lru(cache), blk_type);
  blk->data = sbdi_bc_get_db_for_cache_idx(cache, idx_get_lru(cache));
  idx_inc_lru(cache);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bc_dirty_blk(sbdi_bc_t *cache, uint32_t phy_idx)
{
  if (!cache || phy_idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(cache, phy_idx);
  SBDI_BC_CHK_IDX_POS(idx_pos);
  sbdi_bc_set_blk_dirty(cache, idx_pos);
  if (sbdi_bc_is_mngt_blk(cache, idx_pos)
      && SBDI_BC_IDX_P1(idx_pos) != idx_get_lru(cache)) {
    // This is a management block and it's not already at the top of the
    // cache list ==> bump it up
    SBDI_BC_ERR_CHK(sbdi_bc_swap(cache, idx_pos, SBDI_BC_IDX_P1(idx_pos)));
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bc_evict_blk(sbdi_bc_t *cache, uint32_t phy_idx)
{
  if (!cache || phy_idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(cache, phy_idx);
  // Test if the block marked for eviction is found. If not, this is bad news,
  // as the only place where this function is called, is when a cache
  // reservation must be invalidated, because a block could not be loaded.
  // This means the block to be evicted must be in cache at this point.
  SBDI_BC_CHK_IDX_POS(idx_pos);
  idx_invalidate_phy_idx(cache, idx_pos);
  if (idx_pos == idx_get_lru(cache)) {
    return SBDI_SUCCESS;
  }
  // need to find out if there are any valid blocks between lru and idx_pos.
  // If so swap with the closest to LRU.
  uint32_t swp_last = idx_pos;
  uint32_t swp = idx_pos;
  do {
    SBDI_BC_DEC_IDX(swp);
    if (sbdi_bc_is_valid(idx_get_phy_idx(cache, swp))) {
      SBDI_BC_ERR_CHK(sbdi_bc_swap(cache, swp_last, swp));
      swp_last = swp;
    }
  } while (swp != idx_get_lru(cache));
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
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
    if (sbdi_bc_is_valid_and_dirty(cache, i)
        && !sbdi_bc_is_mngt_blk(cache, i)) {
      // Not a management block, but dirty ==> sync in the first round
      sbdi_block_init(&to_sync, idx->list[i].block_idx,
          sbdi_bc_get_db_address(cache, idx->list[i].cache_idx));
      SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
      sbdi_bc_clear_blk_dirty(cache, i);
    }
  }
  // Second round: sync out all remaining dirty management blocks
  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    if (sbdi_bc_is_valid_and_dirty(cache, i)) {
      sbdi_block_init(&to_sync, idx->list[i].block_idx,
          sbdi_bc_get_db_address(cache, idx->list[i].cache_idx));
      SBDI_BC_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
      sbdi_bc_clear_blk_dirty(cache, i);
    }
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
#ifdef SBDI_CACHE_PROFILE
void sbdi_bc_print_stats(sbdi_bc_t *cache)
{
  printf("%" PRIu64 " hits/%" PRIu64 " misses; ratio: %f\n", cache->hits,
      cache->misses, (double) cache->hits / (double) cache->misses);
}
#endif
