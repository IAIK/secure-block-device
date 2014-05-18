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

#define INC_IDX(IDX) do {IDX = ((IDX) + 1) % SBDI_CACHE_MAX_SIZE;} while (0)
#define DEC_IDX(IDX) do {IDX = ((IDX) + 1) % SBDI_CACHE_MAX_SIZE;} while (0)
#define  IDX_P1(IDX) ((IDX+1) % SBDI_CACHE_MAX_SIZE)

sbdi_bc_t *sbdi_bc_cache_create(void)
{
  sbdi_bc_t *cache = malloc(sizeof(sbdi_bc_t));
  memset(cache, 0xFF, sizeof(sbdi_bc_t));
  // Initialize lru
  cache->index.lru = 0;
  // Initialize block cache index numbers
  for (uint32_t i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    cache->index.list[i].cache_idx = i;
  }
  return cache;
}
void sbdi_bc_cache_destroy(sbdi_bc_t *cache)
{
  free(cache);
}

static inline sbdi_error_t sbdi_bc_swap(sbdi_bc_idx_t *idx, uint32_t idx_1,
    uint32_t idx_2)
{
  if (!idx || idx_1 > SBDI_CACHE_MAX_SIZE || idx_2 > SBDI_CACHE_MAX_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }

  idx->list[idx_1].block_idx = idx->list[idx_1].block_idx
      ^ idx->list[idx_2].block_idx;
  idx->list[idx_2].block_idx = idx->list[idx_1].block_idx
      ^ idx->list[idx_2].block_idx;
  idx->list[idx_1].block_idx = idx->list[idx_1].block_idx
      ^ idx->list[idx_2].block_idx;

  idx->list[idx_1].cache_idx = idx->list[idx_1].cache_idx
      ^ idx->list[idx_2].cache_idx;
  idx->list[idx_2].cache_idx = idx->list[idx_1].cache_idx
      ^ idx->list[idx_2].cache_idx;
  idx->list[idx_1].cache_idx = idx->list[idx_1].cache_idx
      ^ idx->list[idx_2].cache_idx;

  return SBDI_SUCCESS;
}

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
        sbdi_bc_swap(idx, cdt, IDX_P1(cdt));
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

sbdi_error_t sbdi_bc_cache_blk(sbdi_bc_t *cache, sbdi_block_t *blk)
{
  if (!cache || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  blk->data = NULL;
  sbdi_bc_find_blk(cache, blk);
  if (blk->data) {
    return SBDI_SUCCESS;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  idx->list[idx->lru].block_idx = blk->idx;
  blk->data = cache->store + idx->list[idx->lru].cache_idx;
  INC_IDX(idx->lru);
  return SBDI_SUCCESS;
}

#ifdef SBDI_CACHE_PROFILE
void sbdi_bc_print_stats(sbdi_bc_t *cache)
{
  printf("%" PRIu64 " hits/%" PRIu64 " misses; ratio: %f\n", cache->hits, cache->misses, (double)cache->hits/(double)cache->misses);
}
#endif
