/*
 * sbdi_blic.h
 *
 * Secure Block Device Interface Block Layer Index Conversion library
 *
 * This header contains all functions used for converting between logic and
 * physical block indices and computing management block index from diverse
 * input indices.
 *
 *  Created on: May 28, 2014
 *      Author: dhein
 */

#ifndef SBDI_BLIC_H_
#define SBDI_BLIC_H_

#include "sbdi_config.h"

#include <assert.h>
#include <stdint.h>

/*!
 * \brief Determines if the given physical block index points to a management
 * block
 *
 * @param phy the physical block index
 * @return true if the given physical index points to a management block;
 * false otherwise
 */
static inline int sbdi_blic_is_phy_mng_blk(uint32_t phy)
{
  assert(phy > 0);
  return ((phy - 1) % (SBDI_MNGT_BLOCK_ENTRIES + 1)) == 0;
}

/*!
 * \brief Converts a logical block index into the number of management blocks
 * required up to the logical block index
 * @param log the logical block index
 * @return the number of management blocks required for the given logical
 * index
 */
static inline uint32_t sbdi_blic_log_to_mng_blk_nbr(uint32_t log)
{
  return log / SBDI_MNGT_BLOCK_ENTRIES;
}

/*!
 * \brief Converts the given physical block index into the number of
 * management blocks required up to the physical index
 * @param phy the physical block index
 * @return the number of management blocks required for the given physical
 *  index
 */
static inline uint32_t sbdi_blic_phy_to_mng_blk_nbr(uint32_t phy)
{
  assert(phy > 0);
  return (phy - 1) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
}

static inline uint32_t sbdi_blic_phy_mng_to_mng_blk_nbr(uint32_t phy_mng)
{
  assert(phy_mng > 0);
  assert(sbdi_blic_is_phy_mng_blk(phy_mng));
  return (phy_mng - 1) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
}

static inline uint32_t sbdi_blic_log_to_phy_mng_blk(uint32_t log)
{
  // TODO replace with mng_blk_nbr * (SBDI_MNGT_BLOCK_ENTRIES + 1) + 1
  return (sbdi_blic_log_to_mng_blk_nbr(log) * SBDI_MNGT_BLOCK_ENTRIES)
      + sbdi_blic_log_to_mng_blk_nbr(log) + 1;
}

static inline uint32_t sbdi_blic_log_to_phy_dat_blk(uint32_t log)
{
  return log + sbdi_blic_log_to_mng_blk_nbr(log) + 2;
}

static inline uint32_t sbdi_blic_log_to_mng_tag_idx(uint32_t log)
{
  return log % SBDI_MNGT_BLOCK_ENTRIES;
}

static inline uint32_t sbdi_bl_idx_phy_to_log(uint32_t phy)
{
  if (phy < 2) {
    // TODO Error handling?
    return UINT32_MAX;
  }
  return (phy - 2) - (phy - 2) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
}

static inline uint32_t sbdi_bl_idx_phy_to_mng(uint32_t phy)
{
  assert(phy > 1);
  uint32_t tmp = (phy - 2) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
  return tmp * (SBDI_MNGT_BLOCK_ENTRIES + 1) + 1;
}

/*!
 * \brief Computes the physical management block address from the management
 * block index
 * @param mng_idx
 * @return
 */
static inline uint32_t sbdi_bl_mng_idx_to_mng_phy(uint32_t mng_idx)
{
  return (mng_idx * (SBDI_MNGT_BLOCK_ENTRIES + 1)) + 1;
}

#endif /* SBDI_BLIC_H_ */
