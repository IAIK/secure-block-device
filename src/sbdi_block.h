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
#include "sbdi_blic.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t sbdi_db_t[SBDI_BLOCK_SIZE];

typedef struct sbdi_block {
  uint32_t idx;
  sbdi_db_t *data;
} sbdi_block_t;

static inline void sbdi_block_init(sbdi_block_t *blk, uint32_t blk_idx,
    sbdi_db_t *blk_data)
{
  assert(blk);
  // TODO assert block index valid or UINT32_MAX?
  blk->idx = blk_idx;
  blk->data = blk_data;
}

static inline void sbdi_block_invalidate(sbdi_block_t *blk)
{
  assert(blk);
  blk->idx = UINT32_MAX;
  blk->data = NULL;
}

#endif /* SBDI_BLOCK_H_ */

#ifdef __cplusplus
}
#endif
