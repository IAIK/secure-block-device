/*
 * sbdi_block.h
 *
 *  Created on: May 18, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_BLOCK_H_
#define SBDI_BLOCK_H_

#include "sbdi_config.h"

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t sbdi_db_t[SBDI_BLOCK_SIZE];

typedef struct sbdi_block {
  uint32_t idx;
  sbdi_db_t *data;
} sbdi_block_t;

typedef struct sbdi_block_pair {
  uint32_t mng_nbr;
  uint32_t tag_idx;
  sbdi_block_t mng_dat;
  sbdi_block_t *mng;
  sbdi_block_t blk_dat;
  sbdi_block_t *blk;
} sbdi_block_pair_t;

static inline sbdi_error_t sbdi_block_init(sbdi_block_t *blk, uint32_t blk_idx,
    sbdi_db_t *blk_data)
{
  if (!blk) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  blk->idx = blk_idx;
  blk->data = blk_data;
  return SBDI_SUCCESS;
}

static inline sbdi_error_t sbdi_block_invalidate(sbdi_block_t *blk)
{
  if (!blk) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  blk->idx = UINT32_MAX;
  blk->data = NULL;
  return SBDI_SUCCESS;
}

#endif /* SBDI_BLOCK_H_ */

#ifdef __cplusplus
}
#endif
