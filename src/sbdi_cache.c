/*
 * sbdi_cache.c
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#include "sbdi_cache.h"

#include <stdlib.h>
#include <string.h>

#define INC_IDX(IDX) do {IDX = ((IDX) + 1) % SBDI_CACHE_MAX_SIZE;} while (0)
#define DEC_IDX(IDX) do {IDX = ((IDX) + 1) % SBDI_CACHE_MAX_SIZE;} while (0)
#define  IDX_P1(IDX) ((IDX+1) % SBDI_CACHE_MAX_SIZE)


sbdi_bc_t *sbdi_cache_create(void)
{
  sbdi_bc_t *cache = malloc(sizeof(sbdi_bc_t));
  memset(cache, 0xFF, sizeof(sbdi_bc_t));
  // Initialize block cache index numbers
  for (uint32_t i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    cache->index.list[i].cache_idx = i;
  }
  return cache;
}
void sbdi_cache_destroy(sbdi_bc_t *cache)
{
  free(cache);
}

sbdi_error_t sbdi_cache_blk(sbdi_bc_t *cache, uint32_t blk_idx,
    sbdi_block_t *blk)
{
  if (!cache || blk_idx > SBDI_CACHE_MAX_SIZE || !blk) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
//  sbdi_bc_idx_t idx = cache->index;
//
//  *blk = cache->cache[idx->lru];
//  idx->lru = idx->lru + 1 % SBDI_CACHE_MAX_SIZE;
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_find_blk(sbdi_bc_t *cache, uint32_t blk_idx,
    sbdi_block_t **blk)
{
  if (!cache || blk_idx > SBDI_CACHE_MAX_SIZE || !blk) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  uint32_t cdt = idx->lru;
  do {
    DEC_IDX(cdt);
    if (idx->list[cdt].block_idx == blk_idx) {
      if (IDX_P1(cdt) == idx->lru) {
        *blk = cache->store + idx->list[cdt].cache_idx;
      }
    }
  } while (cdt != idx->lru);

//do {
//  uint32_t cdt = idx->lru-1 % 4;
//  if (idx->list[cdt] == blk_idx) {
//    // found the block in the cache, sort it up
//    if ((cdt+1)%SBDI_CACHE_MAX_SIZE) {}
//  }
//}while ()

return SBDI_SUCCESS;
}
