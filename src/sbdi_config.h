/*
 * sbdi_config.h
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#ifndef SBDI_CONFIG_H_
#define SBDI_CONFIG_H_

#include "config.h"
#include "sbdi_err.h"

#include <stdint.h>
#include <assert.h>
#include <stddef.h>

/*!
 * \brief the block data data type for storing actual block data
 */
typedef uint8_t sbdi_bl_data_t[SBDI_BLOCK_SIZE];

/*!
 * \brief the basic block data type combining a block index with the block
 * data
 *
 * The block itself does not distinguish between physical block indexes and
 * logical block indices. The user of this data type has to take care of the
 * semantic of the index.
 */
typedef struct sbdi_block {
  uint32_t idx;         //!< the block index
  sbdi_bl_data_t *data; //!< a pointer to the actual block data
} sbdi_block_t;

static inline void sbdi_block_init(sbdi_block_t *blk, uint32_t blk_idx,
    sbdi_bl_data_t *blk_data)
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

#endif /* SBDI_CONFIG_H_ */
