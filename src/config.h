/*
 * config.h
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#ifndef CONFIG_H_
#define CONFIG_H_

// NOTE Requirement MAX BLOCK INDEX < UINT32_MAX!
// #define SBDI_BLOCK_SIZE         4096u //!< The block size of the secure block device interface
#define SBDI_BLOCK_SIZE         2048u //!< The block size of the secure block device interface
#define SBDI_SIZE_MAX           UINT32_C(2147483647)  //!< The maximum size in bytes of the secure block device interface
#define SBDI_BLK_MAX_LOG        (SBDI_SIZE_MAX / SBDI_BLOCK_SIZE) + (((SBDI_SIZE_MAX % SBDI_BLOCK_SIZE) > 0)?1:0)  //!< The maximum number of logical blocks supported by the secure block device interface
#define SBDI_BLOCK_CTR_SIZE     16u //!< The size in bytes of the counter (nonce) used to make every block write unique
#define SBDI_BLOCK_TAG_SIZE     16u //!< The size in bytes of a cryptographic block tag (a mac over a single block)
#define SBDI_MNGT_BLOCK_ENTRIES (SBDI_BLOCK_SIZE/(SBDI_BLOCK_CTR_SIZE + SBDI_BLOCK_TAG_SIZE)) //!< The number of tag/counter entries in a management block
#define SBDI_BLK_MAX_PHY        ((SBDI_BLK_MAX_LOG) + ((SBDI_BLK_MAX_LOG)/(SBDI_MNGT_BLOCK_ENTRIES)) + 2) //!< The maximum number of physical blocks supported by the secure block device interface
#define SBDI_CRYPTO_TYPE_NONE   65535u //!< Cryptographic abstraction layer that implements all crypto implementations as NOPs
#define SBDI_CRYPTO_TYPE_SIV    1u //!< Cryptographic abstraction layer that uses SIV and CMAC for its cryptographic operations
#define SBDI_CRYPTO_TYPE_OCB    2u //!< Cryptographic abstraction layer that uses OCB and CMAC for its cryptographic operations
#define SBDI_CRYPTO_TYPE_HMAC   3u //!< Cryptographic abstraction layer that uses CBC and HMAC for its cryptographic operations
/* Enable runtime cryptographic abstraction layer selection */
#undef SBDI_CRYPTO_TYPE
// #define SBDI_CRYPTO_TYPE        SBDI_CRYPTO_TYPE_OCB /*!< Specify which kind of cryptography to use as default */

#define SBDI_CACHE_MAX_SIZE     16u
#define SBDI_CACHE_PROFILE

#endif /* CONFIG_H_ */
