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
/// layer that uses AES-CBC and HMAC-SHA256.
///
/// This cryptographic abstraction layer is implemented for comparison only.
///
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_HMAC_H_
#define SBDI_HMAC_H_

#include "sbdi_crypto.h"

sbdi_error_t sbdi_hmac_create(sbdi_crypto_t **crypto, const sbdi_key_t key);
void sbdi_hmac_destroy(sbdi_crypto_t *crypto);

#endif /* SBDI_HMAC_H_ */

#ifdef __cplusplus
}
#endif
