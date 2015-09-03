/* Copyright (c) IAIK, Graz University of Technology, 2015.
 * All rights reserved.
 * Contact: http://opensource.iaik.tugraz.at
 * 
 * This file is part of the Secure Block Device Library.
 * 
 * Commercial License Usage
 * Licensees holding valid commercial licenses may use this file in
 * accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and SIC. For further information
 * contact us at http://opensource.iaik.tugraz.at.
 * 
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License as published by the Free Software Foundation version 2.
 * 
 * The Secure Block Device Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with the Secure Block Device Library. If not, see <http://www.gnu.org/licenses/>.
 */
///
/// \file
/// \brief The Secure Block Device Library's data cache interface.
///
/// This specifies the interface for the write back, write allocate data cache
/// used by the SBD to speed up access to frequently accessed data.
///

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_CACHE_H_
#define SBDI_CACHE_H_

#include "sbdi_config.h"

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

#define SBDI_CACHE_SIZE ((SBDI_CACHE_MAX_SIZE)  * (SBDI_BLOCK_SIZE))

typedef enum sbdi_block_cache_block_type {
  SBDI_BC_BT_RESV = 0,
  SBDI_BC_BT_MNGT = SBDI_BC_BT_MNGT_CMP,
  SBDI_BC_BT_DATA = SBDI_BC_BT_DATA_CMP,
} sbdi_bc_bt_t;

typedef sbdi_error_t (*sbdi_bc_sync_fp_t)(void *sync_data, sbdi_block_t *blk);

/*!
 * \brief Determines if the given data block specified by blk is in scope of
 * the management block specified by mng and returns true if this is the case
 *
 * @param mng[in] the identifier of the management block (e.g. physical block
 *                index)
 * @param blk[in] the identifier of the data block (e.g. physical block
 *                index)
 * @return true if the specified data block is in scope of the specified
 *              management block;
 *         false otherwise
 */
typedef int (*sbdi_bc_is_in_scope_fp_t)(const uint32_t mng, const uint32_t blk);

typedef struct sbdi_block_cache_index_element {
  uint32_t block_idx;
  uint32_t cache_idx;
  int flags;
} sbdi_bc_idx_elem_t;

typedef struct sbdi_block_cache_index {
  uint32_t lru;
  sbdi_bc_idx_elem_t list[SBDI_CACHE_MAX_SIZE];
} sbdi_bc_idx_t;

typedef struct sbdi_block_cache_callbacks {
  void *sync_data;
  sbdi_bc_sync_fp_t sync;
  sbdi_bc_is_in_scope_fp_t in_scope;
} sbdi_bc_cb_t;

typedef struct sbdi_block_cache {
#ifdef SBDI_CACHE_PROFILE
  uint64_t hits;
  uint64_t misses;
  uint64_t bumps;
#endif
  sbdi_bc_cb_t cbs;
  sbdi_bc_idx_t index;
  sbdi_bl_data_t store[SBDI_CACHE_MAX_SIZE];
} sbdi_bc_t;

/*!
 * \brief Creates a new cache for a secure block device interface
 *
 * Allocates the memory required for the cache. To clean up the cache, call
 * sbdi_bc_cache_destroy(). None of the arguments to this function may be
 * null!
 *
 * @param sync_data[in] a void pointer to a data type that might be required
 *                  by the sync callback function
 * @param sync[in] a function pointer to the sync callback function, which is
 *                 used to synchronize dirty data in the cache before this
 *                 data is evicted from the cache
 * @param in_scope[in] a function pointer to the is_in_scope callback
 *                     function. This function is used by the cache to
 *                     determine which data blocks are in-scope (dependent
 *                     on) a specific management block
 * @return a freshly created cache data type instance if the operation
 *         succeeds; NULL otherwise
 */
sbdi_bc_t *sbdi_bc_cache_create(void *sync_data, sbdi_bc_sync_fp_t sync,
    sbdi_bc_is_in_scope_fp_t in_scope);

/*!
 * \brief Destroys the given cache by overwriting the complete cache memory
 * and freeing all resources associated with the cache
 *
 * The caller has to ensure that all data in the cache is synchronized,
 * before calling this function, otherwise the data in the cache will be
 * lost.
 *
 * @param cache[in] a pointer to the cache to destroy
 */
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
static inline sbdi_bl_data_t *sbdi_bc_get_db_for_cache_idx(sbdi_bc_t *cache,
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
  if (!cache || !sbdi_block_is_valid_phy(blk_idx)) {
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

/*!
 * \brief Determines if the element in the cache index at the given index
 * position points to a valid physical block address
 *
 * @param cache[in] a pointer to the cache witch contains the element to
 *                  check
 * @param idx_pos[in] the position of the element to check in the cache index
 * @return true if the element in the cache index at the given position\
 *              points to a valid physical address;
 *         false otherwise
 */
static inline int sbdi_bc_is_elem_valid_phy(const sbdi_bc_t *cache,
    const uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return sbdi_block_is_valid_phy(cache->index.list[idx_pos].block_idx);
}

/*!
 * \brief Determines if the element in the cache index at the given index
 * position is dirty
 *
 * @param cache[in] a pointer to the cache witch contains the element to
 *                  check
 * @param idx_pos[in] the position of the element to check in the cache index
 * @return true if the element in the cache index at the given position is
 *              dirty;
 *         false otherwise
 */
static inline int sbdi_bc_is_elem_dirty(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return cache->index.list[idx_pos].flags & SBDI_BC_BF_DIRTY_CMP;
}

/*!
 * \brief Determines if the element in the cache index at the given index
 * position is dirty and points to a valid physical block address
 *
 * @param cache[in] a pointer to the cache witch contains the element to
 *                  check
 * @param idx_pos[in] the position of the element to check in the cache index
 * @return true if the element in the cache index at the given position is
 *              dirty and points to a valid physical block address;
 *         false otherwise
 */
static inline int sbdi_bc_is_elem_valid_and_dirty(sbdi_bc_t *cache,
    uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return sbdi_block_is_valid_phy(cache->index.list[idx_pos].block_idx)
      && sbdi_bc_is_elem_dirty(cache, idx_pos);
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

static inline sbdi_bc_bt_t sbdi_bc_get_blk_type(sbdi_bc_t *cache,
    uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return (sbdi_bc_bt_t) (cache->index.list[idx_pos].flags & UINT8_MAX);
}

static inline int sbdi_bc_is_elem_mngt_blk(sbdi_bc_t *cache, uint32_t idx_pos)
{
  assert(cache && sbdi_bc_idx_is_valid(idx_pos));
  return sbdi_bc_get_blk_type(cache, idx_pos) == SBDI_BC_BT_MNGT;
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
