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

#define SBDI_BC_BT_MNGT_CMP 1
#define SBDI_BC_BT_DATA_CMP 2
#define SBDI_BC_BF_DIRTY_CMP 256
#define SBDI_BC_BF_DIRTY_CLEAR UINT16_MAX ^ SBDI_BC_BF_DIRTY_CMP

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

sbdi_error_t sbdi_bc_find_blk(sbdi_bc_t *cache, sbdi_block_t *blk);
sbdi_error_t sbdi_bc_cache_blk(sbdi_bc_t *cache, sbdi_block_t *blk,
    sbdi_bc_bt_t blk_type);
sbdi_error_t sbdi_bc_dirty_blk(sbdi_bc_t *cache, sbdi_block_t *blk);
sbdi_error_t sbdi_bc_evict_blk(sbdi_bc_t *cache, sbdi_block_t *blk);
sbdi_error_t sbdi_bc_sync(sbdi_bc_t *cache);

static inline int sbdi_bc_is_valid(uint32_t blk_idx) {
  return blk_idx <= SBDI_BLOCK_MAX_INDEX;
}

static inline int sbdi_bc_is_blk_dirty(int flags)
{
  return flags & SBDI_BC_BF_DIRTY_CMP;
}

static inline int sbdi_bc_is_valid_and_dirty(sbdi_bc_idx_elem_t *elem)
{
  return elem->block_idx <= SBDI_BLOCK_MAX_INDEX
      && sbdi_bc_is_blk_dirty(elem->flags);
}

static inline void sbdi_bc_set_blk_dirty(sbdi_bc_idx_elem_t *blk)
{
  blk->flags |= SBDI_BC_BF_DIRTY_CMP;
}

static inline void sbdi_bc_clear_blk_dirty(sbdi_bc_idx_elem_t *blk)
{
  blk->flags &= SBDI_BC_BF_DIRTY_CLEAR;
}

static inline int sbdi_bc_is_mngt_blk(int flags)
{
  return (flags & UINT8_MAX) == SBDI_BC_BT_MNGT;
}

/*!
 * \brief sets the block type of a specific cache index element
 *
 * Warning this function clears the dirty flag!
 *
 * @param elem the cache index element to set the type of
 * @param blk_type the type to set the block to
 */
static inline void sbdi_bc_set_blk_type(sbdi_bc_idx_elem_t *elem,
    sbdi_bc_bt_t blk_type)
{
  elem->flags = blk_type;
}

static inline int sbdi_bc_is_data_blk(int flags)
{
  return (flags & UINT8_MAX) == SBDI_BC_BT_DATA;
}

#ifdef SBDI_CACHE_PROFILE
void sbdi_bc_print_stats(sbdi_bc_t *cache);
#endif

#endif /* SBDI_CACHE_H_ */

#ifdef __cplusplus
}
#endif
