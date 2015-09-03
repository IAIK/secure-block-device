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
/// \brief Specifies the Secure Block Device Library's cryptographic
/// abstraction layer.
///
/// The cryptographic abstraction layer hides the implementation of the actual
/// authenticating encryption used to achieve the data security goals. It also
/// hides the implementation of the message authentication code used to
/// protect the integrity of the management blocks.
///

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_CRYPTO_H_
#define SBDI_CRYPTO_H_

#include "sbdi_config.h"
#include "sbdi_ctr_128b.h"

#include <stdint.h>

typedef uint8_t sbdi_key_t[32];

typedef sbdi_error_t (*sbdi_encrypt)(void *ctx, const uint8_t *pt,
    const int pt_len, const sbdi_ctr_128b_t *ctr, const uint32_t blk_nbr,
    uint8_t *ct, sbdi_tag_t tag);

typedef sbdi_error_t (*sbdi_decrypt)(void *ctx, const uint8_t *ct,
    const int ct_len, const sbdi_ctr_pkd_t ctr, const uint32_t blk_nbr,
    uint8_t *pt, const sbdi_tag_t tag);

typedef sbdi_error_t (*sbdi_mac)(void *ctx, const unsigned char *msg,
    const int mlen, unsigned char *C, const unsigned char *ad, const int ad_len);

typedef struct sbdi_crypto {
  void *ctx;
  sbdi_encrypt enc;
  sbdi_decrypt dec;
  sbdi_mac mac;
} sbdi_crypto_t;

#endif /* SBDI_CRYPTO_H_ */

#ifdef __cplusplus
}
#endif
