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
/// \brief Specifies the data type used to select the cryptographic abstraction
/// layer to use for the cryptographic operations.
///
/// The Secure Block Device Library supports a number of different
/// cryptographic operations for providing the data security.
///
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_CRYPTO_TYPE_H_
#define SBDI_CRYPTO_TYPE_H_

#include "sbdi_config.h"

/*!
 * \brief Used to select which cryptographic abstraction layer to use
 */
typedef enum sbdi_crypto_type {
  SBDI_CRYPTO_NONE = SBDI_CRYPTO_TYPE_NONE, /*!< Crypto operations implemented as no operations */                                               //!< SBDI_CRYPTO_NONE
  SBDI_CRYPTO_SIV = SBDI_CRYPTO_TYPE_SIV, /*!< Crypto operations implemented using the SIV authenticated encryption mode of operation with AES *///!< SBDI_CRYPTO_SIV
  SBDI_CRYPTO_OCB = SBDI_CRYPTO_TYPE_OCB, /*!< Crypto operations implemented using the OCB authenticated encryption mode of operation with AES */ //!< SBDI_CRYPTO_OCB
  SBDI_CRYPTO_HMAC = SBDI_CRYPTO_TYPE_HMAC, /*!< Cryptographic abstraction layer that uses CBC and HMAC for its cryptographic operations */
} sbdi_crypto_type_t;

#endif /* SBDI_CRYPTO_TYPE_H_ */

#ifdef __cplusplus
}
#endif
