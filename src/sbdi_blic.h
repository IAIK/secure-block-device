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
 * @param phy[in] the physical block index
 * @return true if the given physical index points to a management block;
 * false otherwise
 */
static inline int sbdi_blic_is_phy_mng_blk(const uint32_t phy)
{
  assert(phy > 0);
  return ((phy - 1) % (SBDI_MNGT_BLOCK_ENTRIES + 1)) == 0;
}

/*!
 * \brief Converts a logical block index into the number of management blocks
 * required up to the logical block index
 * @param log[in] the logical block index
 * @return the number of management blocks required for the given logical
 * index
 */
static inline uint32_t sbdi_blic_log_to_mng_blk_nbr(const uint32_t log)
{
  return log / SBDI_MNGT_BLOCK_ENTRIES;
}

/*!
 * \brief Converts the given physical block index into the number of
 * management blocks required up to the physical index
 * @param phy[in] the physical block index
 * @return the number of management blocks required for the given physical
 * index
 */
static inline uint32_t sbdi_blic_phy_to_mng_blk_nbr(const uint32_t phy)
{
  assert(phy > 0);
  return (phy - 1) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
}

/*!
 * \brief Converts the given physical block index into the number of
 * management blocks required up to the physical index and checks that the
 * given index points to a management block
 * @param phy_mng[in] the physical management block index
 * @return the number of management blocks required for the given physical
 * index
 */
static inline uint32_t sbdi_blic_phy_mng_to_mng_blk_nbr(const uint32_t phy_mng)
{
  assert(phy_mng > 0);
  assert(sbdi_blic_is_phy_mng_blk(phy_mng));
  return (phy_mng - 1) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
}

/*!
 * \brief Converts the given logical index into the physical management block
 * index of the management block that stores the management information for
 * the logical block specified by the given index
 * @param log[in] the logical block index
 * @return the physical management block index that stores the management
 * information for the data block specified by the given logical index
 */
static inline uint32_t sbdi_blic_log_to_phy_mng_blk(const uint32_t log)
{
  return (sbdi_blic_log_to_mng_blk_nbr(log) * (SBDI_MNGT_BLOCK_ENTRIES + 1)) + 1;
}

/*!
 * \brief Converts the given logical data block index into the corresponding
 * physical data block index
 * @param log[in] the logical data block index to convert
 * @return the physical data block index for the given logical block index
 */
static inline uint32_t sbdi_blic_log_to_phy_dat_blk(const uint32_t log)
{
  return log + sbdi_blic_log_to_mng_blk_nbr(log) + 2;
}

/*!
 * \brief Computes the position of a data block's tag in its management block
 *
 * Each data block is associated with a management block. The management
 * block stores the block counter used to make the last encryption of the
 * data block unique and also the tag(MAC) that was computed of the data
 * block. The tag and the counter for a specific data block are stored in the
 * management block at a position depending on the data blocks logical index.
 * This function computes this position.
 *
 * @param log[in] the logical data block index
 * @return the position of a data block's tag from the management block base
 * address
 */
static inline uint32_t sbdi_blic_log_to_mng_tag_pos(const uint32_t log)
{
  return log % SBDI_MNGT_BLOCK_ENTRIES;
}

/*!
 * \brief Converts a physical data block index into its corresponding logical
 * index
 *
 * This function asserts that the given index is greater than one (otherwise
 * is either points to the header, or is the first management block) and
 * makes sure the given physical index does not point to a management block!
 *
 * @param phy_dat[in] the physical data block index to convert into a logical
 * data block index
 * @return the logical data block index for the given physical data block
 * index
 */
static inline uint32_t sbdi_blic_phy_dat_to_log(const uint32_t phy_dat)
{
  assert(phy_dat > 1 && !sbdi_blic_is_phy_mng_blk(phy_dat));
  return (phy_dat - 2) - (phy_dat - 2) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
}

/*!
 * \brief Computes a physical management block index from a physical data
 * block index
 *
 * This function asserts that the given index is greater than one (otherwise
 * is either points to the header, or is the first management block) and
 * makes sure the given physical index does not point to a management block!
 *
 * @param phy[in] the physical data block index to compute the physical
 * management block index for
 * @return the physical management block index for the given physical data
 * block index
 */
static inline uint32_t sbdi_blic_phy_dat_to_phy_mng_blk(const uint32_t phy_dat)
{
  assert(phy_dat > 1 && !sbdi_blic_is_phy_mng_blk(phy_dat));
  uint32_t tmp = (phy_dat - 2) / (SBDI_MNGT_BLOCK_ENTRIES + 1);
  return tmp * (SBDI_MNGT_BLOCK_ENTRIES + 1) + 1;
}

/*!
 * \brief Computes the physical management block index from the given
 * management block number
 *
 * @param mng_blk_nbr[in] the management block number to compute the physical
 * management block index for
 * @return the physical management block index for the given management
 * number
 */
static inline uint32_t sbdi_blic_mng_blk_nbr_to_mng_phy(const uint32_t mng_blk_nbr)
{
  return (mng_blk_nbr * (SBDI_MNGT_BLOCK_ENTRIES + 1)) + 1;
}

#endif /* SBDI_BLIC_H_ */
