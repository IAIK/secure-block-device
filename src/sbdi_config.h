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

#define SBDI_BLOCK_INDEX_INVALID UINT32_MAX

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

/*!
 * \brief Initializes a secure block device interface block with the given
 * block index and block data pointer
 *
 * This function is purely for initialization, the block needs to be
 * allocated first by the caller.
 *
 * @param blk[inout] a pointer to the block to initialize
 * @param blk_idx[in] the index of the block
 * @param blk_data[in] a pointer to the block data
 */
static inline void sbdi_block_init(sbdi_block_t *blk, const uint32_t blk_idx,
    sbdi_bl_data_t *blk_data)
{
  assert(blk && blk_idx < SBDI_BLOCK_INDEX_INVALID);
  blk->idx = blk_idx;
  blk->data = blk_data;
}

/*!
 * \brief Invalidates a given secure block device block by setting its block
 * index to SBDI_BLOCK_INDEX_INVALID
 * @param blk[in] a pointer to the block to invalidate
 */
static inline void sbdi_block_invalidate(sbdi_block_t *blk)
{
  assert(blk);
  blk->idx = SBDI_BLOCK_INDEX_INVALID;
  blk->data = NULL;
}

#endif /* SBDI_CONFIG_H_ */
