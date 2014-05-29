/*
 * config.h
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#ifndef CONFIG_H_
#define CONFIG_H_

// TODO Requirement MAX BLOCK INDEX < UINT32_MAX!
#define SBDI_BLOCK_SIZE         4096u
#define SBDI_SIZE_MAX           UINT32_C(2147483647)  //!< The maximum size of a file */
#define SBDI_BLK_MAX_LOG        (SBDI_SIZE_MAX / SBDI_BLOCK_SIZE)  //!< The maximum number of logical blocks supported by the secure block device interface
#define SBDI_BLOCK_CTR_SIZE     16u
#define SBDI_BLOCK_TAG_SIZE     16u
#define SBDI_MNGT_BLOCK_ENTRIES (SBDI_BLOCK_SIZE/(SBDI_BLOCK_CTR_SIZE + SBDI_BLOCK_TAG_SIZE))
#define SBDI_BLK_MAX_PHY        ((SBDI_BLK_MAX_LOG) + (SBDI_MNGT_BLOCK_ENTRIES) +2) //!< The maximum number of physical blocks supported by the secure block device interface

#define SBDI_CACHE_MAX_SIZE                                16u
#define SBDI_CACHE_PROFILE


#endif /* CONFIG_H_ */
