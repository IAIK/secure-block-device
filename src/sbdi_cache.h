/*
 * sbdi_cache.h
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_CACHE_H_
#define SBDI_CACHE_H_

#include "sbdi_config.h"
#include "sbdi_block.h"

#include <stdint.h>
#include <assert.h>

#define SBDI_BC_BT_MNGT_CMP 1
#define SBDI_BC_BT_DATA_CMP 2
#define SBDI_BC_BF_DIRTY_CMP 256
#define SBDI_BC_BF_DIRTY_CLEAR (UINT16_MAX ^ SBDI_BC_BF_DIRTY_CMP)

#define  SBDI_BC_IDX_P1(IDX) ((IDX+1) % SBDI_CACHE_MAX_SIZE)
#define  SBDI_BC_IDX_S1(IDX) ((IDX-1) % SBDI_CACHE_MAX_SIZE)
#define SBDI_BC_INC_IDX(IDX) do {IDX = SBDI_BC_IDX_P1(IDX);} while (0)
#define SBDI_BC_DEC_IDX(IDX) do {IDX = SBDI_BC_IDX_S1(IDX);} while (0)

typedef enum sbdi_block_cache_block_type {
  SBDI_BC_BT_RESV = 0,
  SBDI_BC_BT_MNGT = SBDI_BC_BT_MNGT_CMP,
  SBDI_BC_BT_DATA = SBDI_BC_BT_DATA_CMP,
} sbdi_bc_bt_t;

typedef sbdi_error_t (*sbdi_sync_fp_t)(void *sync_data, sbdi_block_t *blk);

typedef struct sbdi_block_cache_index_element {
  uint32_t block_idx;
  uint32_t cache_idx;
  int flags;
} sbdi_bc_idx_elem_t;

typedef struct sbdi_block_cache_index {
  uint32_t lru;
  sbdi_bc_idx_elem_t list[SBDI_CACHE_MAX_SIZE];
} sbdi_bc_idx_t;

typedef struct sbdi_block_cache {
#ifdef SBDI_CACHE_PROFILE
  uint64_t hits;
  uint64_t misses;
#endif
  sbdi_sync_fp_t sync;
  void *sync_data;
  sbdi_bc_idx_t index;
  sbdi_db_t store[SBDI_CACHE_MAX_SIZE];
} sbdi_bc_t;

sbdi_bc_t *sbdi_bc_cache_create(sbdi_sync_fp_t sync, void *sync_data);
void sbdi_bc_cache_destroy(sbdi_bc_t *cache);

/*!
 * \brief Determines a cache data block element index based on the position
 * of a specific cache index element
 * @param cache the cache data type instance to operate on
 * @param idx_pos the position of the cache index element for which to obtain
 * the cache data block element index
 * @return the cache data block element index for the specified cache index
 * element position
 */
static inline uint32_t sbdi_bc_idx_get_cache_idx(sbdi_bc_t *cache,
    uint32_t idx_pos)
{
  assert(cache && idx_pos < SBDI_CACHE_MAX_SIZE);
  assert(cache->index.list[idx_pos].cache_idx < SBDI_CACHE_MAX_SIZE);
  return cache->index.list[idx_pos].cache_idx;
}

/*!
 * \brief Computes the address of a cache data block based on the given cache
 * index position
 *
 * @param cache the cache data type instance to obtain the cache data block
 * from
 * @param idx_pos the cache index element position from which to obtain the
 * cache block address
 * @return the memory address of the cache data block
 */
static inline sbdi_db_t *sbdi_bc_get_db_for_cache_idx(sbdi_bc_t *cache,
    uint32_t idx_pos)
{
  assert(cache && idx_pos < SBDI_CACHE_MAX_SIZE);
  return &cache->store[sbdi_bc_idx_get_cache_idx(cache, idx_pos)];
}

/*!
 * \brief looks up if a block with the given physical block index is in the
 * cache and returns the position of the cache element in the caches index
 *
 * @param cache the cache data type instance in which to look for the block
 * @param blk_idx the physical block index to look for
 * @return the position of the element in the cache index
 */
static inline uint32_t sbdi_bc_find_blk_idx_pos(sbdi_bc_t *cache,
    uint32_t blk_idx)
{
  if (!cache || blk_idx > SBDI_BLOCK_MAX_INDEX) {
    return UINT32_MAX;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  uint32_t cdt = idx->lru;
  do {
    SBDI_BC_DEC_IDX(cdt);
    if (idx->list[cdt].block_idx == blk_idx) {
      return cdt;
    }
  } while (cdt != idx->lru);
  return UINT32_MAX;
}

sbdi_error_t sbdi_bc_find_blk(sbdi_bc_t *cache, sbdi_block_t *blk);
sbdi_error_t sbdi_bc_cache_blk(sbdi_bc_t *cache, sbdi_block_t *blk,
    sbdi_bc_bt_t blk_type);
sbdi_error_t sbdi_bc_dirty_blk(sbdi_bc_t *cache, uint32_t phy_idx);
sbdi_error_t sbdi_bc_evict_blk(sbdi_bc_t *cache, uint32_t phy_idx);
sbdi_error_t sbdi_bc_sync(sbdi_bc_t *cache);

/*!
 * \brief Determines if the given physical block index is valid
 *
 * This function checks if the given physical block index value is less than
 * the maximum block index.
 *
 * @param phy_idx the physical block index value to check
 * @return true if the given physical block index value is less than the
 * maximum block index value; false otherwise
 */
static inline int sbdi_bc_is_valid(uint32_t phy_idx)
{
  return phy_idx <= SBDI_BLOCK_MAX_INDEX;
}

/*!
 * \brief Determines if the given block cache index value is valid
 *
 * This function checks if the given cache index value is less than the
 * maximum size of the cache index.
 *
 * @param cache_idx the cache index index value to check
 * @return true if the given cache index index value is less than the maximum
 * cache index size; false otherwise
 */
static inline int sbdi_bc_idx_is_valid(uint32_t cache_idx)
{
  return cache_idx < SBDI_CACHE_MAX_SIZE;
}

static inline int sbdi_bc_is_blk_dirty(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return cache->index.list[idx_pos].flags & SBDI_BC_BF_DIRTY_CMP;
}

static inline int sbdi_bc_is_valid_and_dirty(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return sbdi_bc_is_valid(cache->index.list[idx_pos].block_idx)
      && sbdi_bc_is_blk_dirty(cache, idx_pos);
}

static inline void sbdi_bc_set_blk_dirty(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  cache->index.list[idx_pos].flags |= SBDI_BC_BF_DIRTY_CMP;
}

static inline void sbdi_bc_clear_blk_dirty(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  cache->index.list[idx_pos].flags &= SBDI_BC_BF_DIRTY_CLEAR;
}

static inline sbdi_bc_bt_t sbdi_bc_get_blk_type(int flags)
{
  return (sbdi_bc_bt_t) (flags & UINT8_MAX);
}

static inline int sbdi_bc_is_mngt_blk(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return sbdi_bc_get_blk_type(cache->index.list[idx_pos].flags)
      == SBDI_BC_BT_MNGT;
}

/*!
 * \brief computes if the block with the given block index is in scope of the
 * management block with the given index
 *
 * A data block is in scope of a management block if its counter value and
 * tag are stored in the management block. This can be computed from the
 * physical management block index, by simply adding the amount of entries
 * that fit into a management block and see if the physical index of the
 * data block is less than or equal to this number:
 *
 * in_scope(mng_idx, blk_idx) =
 *   blk_idx > mng_idx && blk_idx <= (mng_idx + MNGT_BLOCK_ENTRIES)
 *
 * @param mng_idx the physical block index of a management block
 * @param blk_idx the physical block index of a data block
 * @return true if the data block with the given index is in scope of the
 * management block with the given index
 */
static inline int sbdi_bc_is_in_mngt_scope(uint32_t mng_idx, uint32_t blk_idx)
{
  return blk_idx > mng_idx && blk_idx <= (mng_idx + SBDI_MNGT_BLOCK_ENTRIES);
}

/*!
 *
 * \brief sets the block type of a specific cache index element
 *
 * Warning this function clears the dirty flag!
 *
 * @param cache the cache data type instance containing the index
 * @param idx_pos the cache index element position
 * @param blk_type the type to set the block to
 */
static inline void sbdi_bc_set_blk_type(sbdi_bc_t *cache, uint32_t idx_pos,
    sbdi_bc_bt_t blk_type)
{
  assert(
      cache && idx_pos < SBDI_CACHE_MAX_SIZE && (blk_type == SBDI_BC_BT_DATA || blk_type == SBDI_BC_BT_MNGT));
  cache->index.list[idx_pos].flags = blk_type;
}

#ifdef SBDI_CACHE_PROFILE
void sbdi_bc_print_stats(sbdi_bc_t *cache);
#endif

#endif /* SBDI_CACHE_H_ */

#ifdef __cplusplus
}
#endif
