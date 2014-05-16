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

#include <stdint.h>

typedef struct sbdi_block_cache_index_element {
  uint32_t block_idx;
  uint32_t cache_idx;
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
  sbdi_bc_idx_t index;
  sbdi_block_t store[SBDI_CACHE_MAX_SIZE];
} sbdi_bc_t;

sbdi_bc_t *sbdi_bc_cache_create(void);
void sbdi_bc_cache_destroy(sbdi_bc_t *cache);

sbdi_error_t sbdi_bc_cache_blk(sbdi_bc_t *cache, uint32_t blk_idx,
    sbdi_block_t **blk);
sbdi_error_t sbdi_bc_find_blk(sbdi_bc_t *cache, uint32_t blk_idx,
    sbdi_block_t **blk);

#ifdef SBDI_CACHE_PROFILE
void sbdi_bc_print_stats(sbdi_bc_t *cache);
#endif

#endif /* SBDI_CACHE_H_ */

#ifdef __cplusplus
}
#endif
