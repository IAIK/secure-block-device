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

#include "sbdi_err.h"

#include <stdint.h>

// TODO Requirement MAX BLOCK INDEX < UINT32_MAX!

#define SBDI_BLOCK_SIZE                                  4096u
#define SBDI_SIZE_MAX                     UINT32_C(2147483647)  /*!< The maximum size of a file */
#define SBDI_BLOCK_MAX_INDEX (SBDI_SIZE_MAX / SBDI_BLOCK_SIZE)  /*!< The maximum number of blocks in a file */

#define SBDI_CACHE_MAX_SIZE                                16u


typedef uint8_t sbdi_block_t[SBDI_BLOCK_SIZE];

typedef struct sbdi_block_cache_index_element {
  uint32_t block_idx;
  uint32_t cache_idx;
} sbdi_bc_idx_elem_t;

typedef struct sbdi_block_cache_index {
  uint32_t lru;
  sbdi_bc_idx_elem_t list[SBDI_CACHE_MAX_SIZE];
} sbdi_bc_idx_t;

typedef struct sbdi_block_cache {
  sbdi_bc_idx_t index;
  sbdi_block_t store[SBDI_CACHE_MAX_SIZE];
} sbdi_bc_t;

sbdi_bc_t *sbdi_bc_cache_create(void);
void sbdi_bc_cache_destroy(sbdi_bc_t *cache);

sbdi_error_t sbdi_bc_cache_blk(sbdi_bc_t *cache, uint32_t blk_idx,
    sbdi_block_t **blk);
sbdi_error_t sbdi_bc_find_blk(sbdi_bc_t *cache, uint32_t blk_idx,
    sbdi_block_t **blk);

#endif /* SBDI_CACHE_H_ */

#ifdef __cplusplus
}
#endif
