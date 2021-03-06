/* Copyright (c) IAIK, Graz University of Technology, 2015.
 * All rights reserved.
 * Contact: http://opensource.iaik.tugraz.at
 * 
 * This file is part of the Secure Block Device Library.
 * 
 * Commercial License Usage
 * Licensees holding valid commercial licenses may use this file in
 * accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and SIC. For further information
 * contact us at http://opensource.iaik.tugraz.at.
 * 
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License as published by the Free Software Foundation version 2.
 * 
 * The Secure Block Device Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with the Secure Block Device Library. If not, see <http://www.gnu.org/licenses/>.
 */
///
/// \file
/// \brief Global compile time configuration options for the Secure Block
/// Device Library.
///
#ifndef CONFIG_H_
#define CONFIG_H_

// NOTE Requirement MAX BLOCK INDEX < UINT32_MAX!
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
