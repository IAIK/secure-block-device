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

#define SBDI_BC_CHK_IDX_POS(cache_idx) do {if (!sbdi_bc_idx_is_valid(cache_idx)) {return SBDI_ERR_ILLEGAL_STATE;}} while (0)

#define SWAP(X, Y) do {(X) = (X) ^ (Y); (Y) = (X) ^ (Y); (X) = (X) ^ (Y);} while (0)

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
 * \brief Gets the position of the least recently used cache index element
 *
 * @param cache the cache data type instance of which to get the least
 * recently used cache element
 * @return the position in the cache index of the least recently used element
 */
static inline uint32_t idx_get_lru(sbdi_bc_t *cache)
{
  assert(cache);
  assert(cache->index.lru < SBDI_CACHE_MAX_SIZE);
  return cache->index.lru;
}

/*!
 * \brief Increments the least recently used cache index pointer
 *
 * The cache uses an array as backing store for the cache. This increment
 * function make sure that the pointer does not go beyond the bounds of the
 * cache.
 *
 * @param cache the cache data type instance of which the least recently used
 * index pointer should be incremented
 */
static inline void idx_inc_lru(sbdi_bc_t *cache)
{
  assert(cache);
  SBDI_BC_INC_IDX(cache->index.lru);
  assert(cache->index.lru < SBDI_CACHE_MAX_SIZE);
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
  //assert(cache->index.list[idx].block_idx < SBDI_BLOCK_MAX_INDEX);
  // The above assertion prevents getting invalid indices out of the cache
  return cache->index.list[idx].block_idx;
}

static inline void idx_set_phy_idx(sbdi_bc_t *cache, uint32_t idx, uint32_t val)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE && sbdi_block_is_valid_phy(val));
  cache->index.list[idx].block_idx = val;
}

static inline void idx_invalidate_phy_idx(sbdi_bc_t *cache, uint32_t idx)
{
  assert(cache && idx < SBDI_CACHE_MAX_SIZE);
  cache->index.list[idx].block_idx = UINT32_MAX;
}

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
    idx_invalidate_phy_idx(cache, i);
    // set cache index
    idx_set_cache_idx(cache, i, i);
    // clear flags (Superfluous under calloc)
    cache->index.list[i].flags = 0;
  }
  return cache;
}

//----------------------------------------------------------------------
void sbdi_bc_cache_destroy(sbdi_bc_t *cache)
{
  // TODO make sure block layer syncs the cache before it frees it!
  // Clear all sensitive information from RAM
  if (cache) {
    memset(cache, 0, sizeof(sbdi_bc_t));
  }
  free(cache);
}

/*!
 * \brief Swaps to elements in the block cache index
 * @param idx the block cache index type instance
 * @param idx_1 the index of the first element to swap in the block cache
 * index
 * @param idx_2 the index of the second element to swap in the block cache
 * index
 */
static inline void bc_swap(sbdi_bc_t *cache, uint32_t idx_1,
    uint32_t idx_2)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_1) && sbdi_bc_idx_is_valid(idx_2));
  sbdi_bc_idx_t *idx = bc_get_idx(cache);
  SWAP(idx->list[idx_1].block_idx, idx->list[idx_2].block_idx);
  SWAP(idx->list[idx_1].cache_idx, idx->list[idx_2].cache_idx);
  SWAP(idx->list[idx_1].flags, idx->list[idx_2].flags);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bc_find_blk(sbdi_bc_t *cache, sbdi_block_t *blk)
{
  SBDI_CHK_PARAM(cache && blk && sbdi_block_is_valid_phy(blk->idx));
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(cache, blk->idx);
  if (!sbdi_bc_idx_is_valid(idx_pos)) {
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
    bc_swap(cache, idx_pos, SBDI_BC_IDX_P1(idx_pos));
    blk->data = sbdi_bc_get_db_for_cache_idx(cache, SBDI_BC_IDX_P1(idx_pos));
#ifdef SBDI_CACHE_PROFILE
    cache->hits++;
#endif
    return SBDI_SUCCESS;
  }
}

/*!
 * \brief Synchronizes a cache block specified by its position in the cache
 * index
 *
 * This is a convenience function to facilitate calling the sync callback
 * function. It builds the parameter struct, calls the callback function, and
 * finally clears the dirty flag if synchronizing the block succeeds.
 *
 * @param cache the cache data type instance which contains the data block to
 * synchronize
 * @param idx_pos the position of the cache index element representing the
 * data block to sync
 * @return SBDI_SUCCESS if the synchronization operation succeeds, otherwise
 * it forwards the error code returned by the sync callback.
 */
static inline sbdi_error_t bc_sync_blk(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  sbdi_block_t to_sync;
  sbdi_block_init(&to_sync, idx_get_phy_idx(cache, idx_pos),
      sbdi_bc_get_db_for_cache_idx(cache, idx_pos));
  SBDI_ERR_CHK(cache->sync(cache->sync_data, &to_sync));
  sbdi_bc_clear_blk_dirty(cache, idx_pos);
  return SBDI_SUCCESS;
}

/*!
 *\brief Syncs all data blocks belonging to a specific management block
 * @param cache the cache data type
 * @param mng_idx the cache list index of the cache index element describing
 * the management block
 * @return SBDI_SUCCESS if the operation succeeds, SBDI_ERR_ILLEGAL_PARAM if
 * any of the given parameters is invalid
 */
//static sbdi_error_t sbdi_bc_sync_mngt_blk(sbdi_bc_t *cache, uint32_t mng_idx)
//{
//  assert(cache && sbdi_bc_idx_is_valid(mng_idx));
//  uint32_t mng_phy_idx = idx_get_phy_idx(cache, mng_idx);
//  // Sync out data blocks first and then the corresponding management block
//  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
//    if (sbdi_bc_is_elem_valid_and_dirty(cache, i) && !sbdi_bc_is_elem_mngt_blk(cache, i)
//        && sbdi_blic_is_phy_dat_in_phy_mngt_scope(mng_phy_idx,
//            idx_get_phy_idx(cache, i))) {
//      // Not a management block, but dirty and in scope of the management
//      // block ==> sync
//      SBDI_ERR_CHK(bc_sync_blk(cache, i));
//    }
//  }
//  /* Now sync out the corresponding management block
//   * First we need to check if the call back has already written the
//   * management block. The call back is allowed to do so, because it might
//   * want stronger integrity guarantees, but it must flag the management
//   * block as not dirty any more if this is the case.
//   */
//  if (sbdi_bc_is_elem_dirty(cache, mng_idx)) {
//    return bc_sync_blk(cache, mng_idx);
//  } else {
//    return SBDI_SUCCESS;
//  }
//}

/*!
 * \brief finds the most recently used element in the cache index that is
 * in-scope of the management block specified by its physical block index and
 * returns its cache index position if such an element exists
 *
 * If such an element does not exist this function returns an invalid cache
 * index position.
 *
 * @param cache[in] a pointer to the cache in which to look for an element
 * that is in-scope of the specified management block
 * @param mng_phy the physical management block index
 * @return the position of the element in the cache index
 */
static inline uint32_t bc_find_in_scope_elem(const sbdi_bc_t *cache,
    const uint32_t mng_phy)
{
  assert(cache);
  const sbdi_bc_idx_t *idx = &cache->index;
  uint32_t cdt = idx->lru;
  do {
    SBDI_BC_DEC_IDX(cdt);
    uint32_t cdt_phy = idx->list[cdt].block_idx;
    // TODO make the inscope function a callback!
    if (sbdi_blic_is_phy_dat_in_phy_mngt_scope(mng_phy, cdt_phy)) {
      return cdt;
    }
  } while (cdt != idx->lru);
  return UINT32_MAX;
}

/*!
 * \brief Bumps-up the cache index element specified by the given start
 * position to the cache index element at the specified end position
 *
 * @param cache[in/out] a pointer to the cache data type instance that
 * contains the index to modify
 * @param srt_pos[in] the position of the index element to bump-up
 * @param end_pos[in] the target position to where to bump the element
 */
static inline void bc_bump_up_blk(sbdi_bc_t *cache, uint32_t srt_pos, const uint32_t end_pos) {
  assert(srt_pos != end_pos && sbdi_bc_idx_is_valid(srt_pos) && sbdi_bc_idx_is_valid(end_pos));
  do {
    bc_swap(cache, srt_pos, SBDI_BC_IDX_P1(srt_pos));
    SBDI_BC_INC_IDX(srt_pos);
  } while (srt_pos != end_pos);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bc_cache_blk(sbdi_bc_t *cache, sbdi_block_t *blk,
    sbdi_bc_bt_t blk_type)
{
  SBDI_CHK_PARAM(
      cache && blk && sbdi_block_is_valid_phy(blk->idx)
          && ((blk_type == SBDI_BC_BT_DATA) || (blk_type == SBDI_BC_BT_MNGT)));
  blk->data = NULL;
  SBDI_ERR_CHK(sbdi_bc_find_blk(cache, blk));
  if (blk->data) {
    return SBDI_SUCCESS;
  }
  int lru = idx_get_lru(cache);
  while (1) {
    if (sbdi_bc_is_elem_valid_phy(cache, lru)) {
      if (sbdi_bc_is_elem_mngt_blk(cache, lru)) {
        /* If the management block has in-scope data blocks that are more
         * recently used than the management block itself, it makes sense to
         * bump up the management block.
         * First, this can happen if a specific management block is already in
         * the cache and a new in-scope data block gets loaded. Now the newly
         * read data block will be the most recently used block and the
         * corresponding management block will less recently used.
         * Second, we bump-up the management block to the most recently used
         * in-scope data block. This SHOULD ensure that all in-scope data
         * blocks get removed before the management block. */
        uint32_t mng_phy = idx_get_phy_idx(cache, lru);
        uint32_t tgt_pos = bc_find_in_scope_elem(cache, mng_phy);
        if (sbdi_bc_idx_is_valid(tgt_pos)) {
          /* In-scope data block exists
           * Need to bump-up management block. If the next higher up block is
           * also a management block we need to do this recursively. */
          bc_bump_up_blk(cache, lru, tgt_pos);
          continue;
        } else {
          /* No in-scope data block
           * Management block can be synchronized out without worrying about
           * in-scope data blocks. */
          if (sbdi_bc_is_elem_dirty(cache, lru)) {
            SBDI_ERR_CHK(bc_sync_blk(cache, lru));
          }
          /* Management block, but not dirty
           * Depending on the integrity guarantees of the sync callback it can
           * happen that a management block is in cache that is not dirty, but
           * still has dirty dependent blocks higher up in the LRU list.
           * Anyway nothing to do in this case. */
          break;
        }
      } else {
        /* Data block ==> sync if dirty */
        if (sbdi_bc_is_elem_dirty(cache, lru)) {
          SBDI_ERR_CHK(bc_sync_blk(cache, lru));
        }
        break;
      }
    } else {
      break;
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
  SBDI_CHK_PARAM(cache && sbdi_block_is_valid_phy(phy_idx));
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(cache, phy_idx);
  SBDI_BC_CHK_IDX_POS(idx_pos);
  // Management blocks should never be set dirty directly
  SBDI_CHK_PARAM(!sbdi_bc_is_elem_mngt_blk(cache, idx_pos));
  sbdi_bc_set_blk_dirty(cache, idx_pos);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bc_evict_blk(sbdi_bc_t *cache, uint32_t phy_idx)
{
  SBDI_CHK_PARAM(cache && sbdi_block_is_valid_phy(phy_idx));
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(cache, phy_idx);
  /* Test if the block marked for eviction is found. If not, this is bad
   * news, as the only place where this function is called, is when a cache
   * reservation must be invalidated, because a block could not be loaded.
   * This means the block to be evicted must be in cache at this point.
   */
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
    if (sbdi_block_is_valid_phy(idx_get_phy_idx(cache, swp))) {
      bc_swap(cache, swp_last, swp);
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
  // Sync out data blocks first and then the corresponding management
  // blocks
  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    if (sbdi_bc_is_elem_valid_and_dirty(cache, i)
        && !sbdi_bc_is_elem_mngt_blk(cache, i)) {
      // Not a management block, but dirty ==> sync in the first round
      // TODO must not trigger automatic management block syncing?
      SBDI_ERR_CHK(bc_sync_blk(cache, i));
    }
  }
  // Second round: sync out all remaining dirty management blocks
  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    if (sbdi_bc_is_elem_valid_and_dirty(cache, i)) {
      SBDI_ERR_CHK(bc_sync_blk(cache, i));
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
