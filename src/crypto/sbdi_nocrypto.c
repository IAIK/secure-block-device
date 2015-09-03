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
/// \brief Implements a Secure Block Device Library cryptographic abstraction
/// layer using no cryptography whatsoever.
///
/// This cryptographic abstraction layer implementation is intended for
/// testing and debugging the Secure Block Device Library. It does not provide
/// any form of protection for the actual data.
///
#include "sbdi_nocrypto.h"

#include <stdlib.h>
#include <string.h>

sbdi_error_t sbdi_nocrypto_encrypt(void *ctx, const uint8_t *pt,
    const int pt_len, const sbdi_ctr_128b_t *ctr, uint32_t blk_nbr, uint8_t *ct,
    sbdi_tag_t tag)
{
  // if the context is non-null then this is used incorrectly
  assert(!ctx);
  SBDI_CHK_PARAM(pt && ctr && pt_len > 0 && tag);
  memset(tag, 0xFF, SBDI_BLOCK_TAG_SIZE);
  if (pt == ct) {
    return SBDI_SUCCESS;
  }
  memcpy(ct, pt, pt_len);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_nocrypto_decrypt(void *ctx, const uint8_t *ct,
    const int ct_len, const sbdi_ctr_pkd_t ctr, const uint32_t blk_nbr,
    uint8_t *pt, const sbdi_tag_t tag)
{
  // if the context is non-null then this is used incorrectly
  assert(!ctx);
  SBDI_CHK_PARAM(
      ct && ct_len > 0 && ctr && sbdi_block_is_valid_phy(blk_nbr) && pt && tag);
  int i;
  // sanity check
  for (i = 0; i < SBDI_BLOCK_TAG_SIZE; ++i) {
    if (tag[i] != 0xFF) {
      return SBDI_ERR_TAG_MISMATCH;
    }
  }
  if (pt == ct) {
    return SBDI_SUCCESS;
  }
  memcpy(pt, ct, ct_len);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_nocrypto_mac(void *ctx, const unsigned char *msg,
    const int mlen, unsigned char *C, const unsigned char *ad, const int ad_len)
{
  // if their is a context, then something is wrong
  assert(!ctx);
  SBDI_CHK_PARAM(msg && mlen > 0 && C);
  memset(C, 0x00, SBDI_BLOCK_TAG_SIZE);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_nocrypto_create(sbdi_crypto_t **crypto, const sbdi_key_t key)
{
  sbdi_crypto_t *c = calloc(1, sizeof(sbdi_crypto_t));
  if (!c) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  c->enc = &sbdi_nocrypto_encrypt;
  c->dec = &sbdi_nocrypto_decrypt;
  c->mac = &sbdi_nocrypto_mac;
  *crypto = c;
  return SBDI_SUCCESS;
}

void sbdi_nocrypto_destroy(sbdi_crypto_t *crypto)
{
  free(crypto);
}
