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

#define  IDX_P1(IDX) ((IDX+1) % SBDI_CACHE_MAX_SIZE)
#define  IDX_S1(IDX) ((IDX-1) % SBDI_CACHE_MAX_SIZE)
#define INC_IDX(IDX) do {IDX = IDX_P1(IDX);} while (0)
#define DEC_IDX(IDX) do {IDX = IDX_S1(IDX);} while (0)

sbdi_bc_t *sbdi_bc_cache_create(sbdi_sync_fp_t sync)
{
  if (sync == NULL) {
    // TODO better error handling?
    return NULL;
  }
  sbdi_bc_t *cache = malloc(sizeof(sbdi_bc_t));
  if (!cache) {
    return NULL;
  }
  memset(cache, 0xFF, sizeof(sbdi_bc_t));
  // set sync callback
  cache->sync = sync;
  // Initialize lru
  cache->index.lru = 0;
  // Initialize block cache index numbers
  for (uint32_t i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    cache->index.list[i].cache_idx = i;
    cache->index.list[i].dirty = 0;
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
  // Make sure the block that gets evicted is in sync!
  sbdi_block_t to_sync;
  if (idx->list[idx->lru].block_idx <= SBDI_BLOCK_MAX_INDEX &&
      idx->list[idx->lru].dirty) {
    sbdi_error_t r;
    sbdi_block_init(&to_sync, idx->list[idx->lru].block_idx,
        cache->store + idx->list[idx->lru].cache_idx);
    r = cache->sync(&to_sync);
    if (r != SBDI_SUCCESS) {
      return r;
    }
    idx->list[idx->lru].dirty = 0;
  }
  idx->list[idx->lru].block_idx = blk->idx;
  blk->data = cache->store + idx->list[idx->lru].cache_idx;
  INC_IDX(idx->lru);
  return SBDI_SUCCESS;
}

static sbdi_error_t sbdi_bc_find_to_evict(sbdi_bc_t *cache, uint32_t blk_idx)
{
  if (!cache || blk_idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_idx_t *idx = &cache->index;
  uint32_t cdt = idx->lru;
  do {
    INC_IDX(cdt);
    if (idx->list[cdt].block_idx == blk_idx) {
      idx->list[cdt].block_idx = UINT32_MAX;
      if (IDX_S1(cdt) == idx->lru) {
        return SBDI_SUCCESS;
      } else {
        sbdi_bc_swap(idx, cdt, IDX_S1(cdt));
        return SBDI_SUCCESS;
      }
    }
  } while (cdt != idx->lru);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_bc_evict_blk(sbdi_bc_t *cache, sbdi_block_t *blk)
{
  if (!cache || !blk || blk->idx > SBDI_BLOCK_MAX_INDEX) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_bc_find_to_evict(cache, blk->idx);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_bc_sync(sbdi_bc_t *cache)
{
  if (!cache) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_error_t r;
  sbdi_block_t to_sync;
  sbdi_bc_idx_t *idx = &cache->index;
  for (int i = 0; i < SBDI_CACHE_MAX_SIZE; ++i) {
    if (idx->list[i].block_idx <= SBDI_BLOCK_MAX_INDEX) {
      sbdi_block_init(&to_sync, idx->list[i].block_idx,
          cache->store + idx->list[i].cache_idx);
      r = cache->sync(&to_sync);
      if (r != SBDI_SUCCESS) {
        return r;
      }
      idx->list[idx->lru].dirty = 0;
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
