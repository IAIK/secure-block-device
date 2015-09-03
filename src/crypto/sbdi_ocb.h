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
/// \brief Specifies a Secure Block Device Library cryptographic abstraction
/// layer that uses AES in OCB mode for data block protection and AES CMAC for
/// management block protection.
///
/// This cryptographic abstraction layer is very efficient, as it uses the
/// one-pass OCB authenticating encryption mode. OCB is patent-encumbered. If
/// you plan on using this cryptographic abstraction layer check
/// http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm .
///
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_OCB_H_
#define SBDI_OCB_H_

#include "sbdi_crypto.h"

/*!
 * \brief Creates a new cryptographic abstraction layer for use with the
 * secure block device interface that uses AES in OCB mode and AES CMAC to
 * implement its cryptographic operations
 *
 * The created cryptographic abstraction layer uses the lower 16 bytes of the
 * key for the CMAC and the upper 16 bytes of the key for OCB.
 *
 * @param crypto[out] a pointer pointer that will be set to the newly created
 * cryptographic abstraction layer
 * @param key[in] the key to use for the cryptographic operations
 * @return SBDI_SUCCESS if the creation of the cryptographic abstraction
 *                      layer is successful;
 *         SBDI_OUT_OF_MEMORY if there was insufficient memory to create the
 *                            OCB context, the SIV (CMAC) context, the
 *                            wrapper context, or the cryptographic
 *                            abstraction layer itself
 *         SBDI_ERR_CRYPTO_FAIL if creation of the OCB AE, or the SIV context
 *                              fails
 */
sbdi_error_t sbdi_ocb_create(sbdi_crypto_t **crypto, const sbdi_key_t key);

/*!
 * \brief Cleans up the given cryptographic abstraction layer by freeing all
 * associated resources
 *
 * Warning: Only apply this function to cryptographic abstraction layers
 * created with the sbdi_ocb_create function!
 *
 * @param crypto[in] the cryptographic abstraction layer to destroy
 */
void sbdi_ocb_destroy(sbdi_crypto_t *crypto);

#endif /* SBDI_OCB_H_ */

#ifdef __cplusplus
}
#endif
