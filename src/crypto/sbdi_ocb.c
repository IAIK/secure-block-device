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
/// \brief Implements Secure Block Device Library cryptographic abstraction
/// layer that uses AES in OCB mode for data block protection and AES CMAC for
/// management block protection.
///
/// This cryptographic abstraction layer is very efficient, as it uses the
/// one-pass OCB authenticating encryption mode. OCB is patent-encumbered. If
/// you plan on using this cryptographic abstraction layer check
/// http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm .
///
#include "sbdi_ocb.h"
#include "sbdi_buffer.h"

#include "ae.h"
#include "siv.h"

#include <stdlib.h>
#include <string.h>

// NOTE OCB truncates counter to 12 bytes

#define SBDI_OCB_KEY_SIZE    16u
#define SBDI_OCB_NONCE_SIZE  (SBDI_BLOCK_CTR_SIZE) - 4
#define SBDI_OCB_AE_KEY_IDX  16u
#define SBDI_OCB_AD_SIZE     (4u + (SBDI_BLOCK_CTR_SIZE))

/*!
 * \brief Wraps the two sub-contexts required by the OCB cryptographic
 * abstraction layer
 *
 * The OCB cryptographic abstraction layer actually uses two different
 * cryptographic operations, an OCB authenticating encryption based on AES,
 * and an AES cmac.
 */
typedef struct sbdi_ocb_ctx {
  ae_ctx *ae_ctx; //!< the OCB authenticating encryption context
  siv_ctx *siv_ctx; //!< the SIV context which is used for computing the CMAC
} sbdi_ocb_ctx_t;

//----------------------------------------------------------------------
sbdi_error_t sbdi_ocb_encrypt(void *ctx, const uint8_t *pt, const int pt_len,
    const sbdi_ctr_128b_t *ctr, const uint32_t blk_nbr, uint8_t *ct,
    sbdi_tag_t tag)
{
  SBDI_CHK_PARAM(
      ctx && pt && pt_len > 0 && ctr && sbdi_block_is_valid_phy(blk_nbr) && ct
          && tag);
  ae_ctx *ae_ctx = ((sbdi_ocb_ctx_t *) ctx)->ae_ctx;

  uint8_t ad[SBDI_OCB_AD_SIZE];
  memset(ad, 0, SBDI_OCB_AD_SIZE);
  sbdi_buffer_t b;
  memset(&b, 0, sizeof(sbdi_buffer_t));

  sbdi_buffer_init(&b, ad, SBDI_OCB_AD_SIZE);
  const unsigned char *ap = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_write_uint32_t(&b, blk_nbr);
  // Truncate the 4 highermost bytes of the counter!
  const unsigned char *np = sbdi_buffer_get_cptr(&b) + 4;
  sbdi_buffer_write_ctr_128b(&b, ctr);

  int cr = ae_encrypt(ae_ctx, np, pt, pt_len, ap, 4, ct, tag, 1);
  if (cr != SBDI_BLOCK_SIZE) {
    return SBDI_ERR_CRYPTO_FAIL;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_ocb_decrypt(void *ctx, const uint8_t *ct, const int ct_len,
    const sbdi_ctr_pkd_t ctr, const uint32_t blk_nbr, uint8_t *pt,
    const sbdi_tag_t tag)
{
  SBDI_CHK_PARAM(
      ctx && ct && ct_len > 0 && ctr && sbdi_block_is_valid_phy(blk_nbr) && pt
          && tag);
  ae_ctx *ae_ctx = ((sbdi_ocb_ctx_t *) ctx)->ae_ctx;

  uint8_t ad[SBDI_OCB_AD_SIZE];
  memset(ad, 0, SBDI_OCB_AD_SIZE);
  sbdi_buffer_t b;
  memset(&b, 0, sizeof(sbdi_buffer_t));

  sbdi_buffer_init(&b, ad, SBDI_OCB_AD_SIZE);
  const unsigned char *ap = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_write_uint32_t(&b, blk_nbr);
  // Truncate the 4 highermost bytes of the counter!
  const unsigned char *np = sbdi_buffer_get_cptr(&b) + 4;
  sbdi_buffer_write_bytes(&b, ctr, SBDI_BLOCK_CTR_SIZE);

  int cr = ae_decrypt(ae_ctx, np, ct, ct_len, ap, 4, pt, tag, 1);
  if (cr != SBDI_BLOCK_SIZE) {
    return SBDI_ERR_CRYPTO_FAIL;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_ocb_mac(void *ctx, const unsigned char *msg, const int mlen,
    unsigned char *C, const unsigned char *ad, const int ad_len)
{
  SBDI_CHK_PARAM(ctx && msg && mlen > 0 && C && ad && ad_len > 0);
  siv_ctx *siv_ctx = ((sbdi_ocb_ctx_t *) ctx)->siv_ctx;
  sbdi_bl_aes_cmac(siv_ctx, ad, ad_len, msg, mlen, C);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_ocb_create(sbdi_crypto_t **crypto, const sbdi_key_t key)
{
  SBDI_CHK_PARAM(crypto && key);
  ae_ctx *ae_ctx = NULL;
  siv_ctx *si_ctx = NULL;
  sbdi_ocb_ctx_t *ocb_ctx = NULL;
  sbdi_crypto_t *c = NULL;

  sbdi_error_t r = SBDI_ERR_UNSPECIFIED;
  ae_ctx = ae_allocate(NULL);
  if (!ae_ctx) {
    r = SBDI_ERR_OUT_Of_MEMORY;
    goto FAIL;
  }
  si_ctx = calloc(1, sizeof(siv_ctx));
  if (!si_ctx) {
    r = SBDI_ERR_OUT_Of_MEMORY;
    goto FAIL;
  }
  ocb_ctx = calloc(1, sizeof(sbdi_ocb_ctx_t));
  if (!ocb_ctx) {
    r = SBDI_ERR_OUT_Of_MEMORY;
    goto FAIL;
  }
  c = calloc(1, sizeof(sbdi_crypto_t));
  if (!c) {
    r = SBDI_ERR_OUT_Of_MEMORY;
    goto FAIL;
  }
// Use the upper 16 bytes of the 32 byte key for OCB
  int cr = ae_init(ae_ctx, key + SBDI_OCB_AE_KEY_IDX, SBDI_OCB_KEY_SIZE,
  SBDI_OCB_NONCE_SIZE, SBDI_BLOCK_TAG_SIZE);
  if (cr != AE_SUCCESS) {
    r = SBDI_ERR_CRYPTO_FAIL;
    goto FAIL;
  }
  cr = siv_init(si_ctx, key, SIV_256);
  if (cr == -1) {
    r = SBDI_ERR_CRYPTO_FAIL;
    goto FAIL;
  }
  ocb_ctx->ae_ctx = ae_ctx;
  ocb_ctx->siv_ctx = si_ctx;
  c->ctx = ocb_ctx;
  c->enc = &sbdi_ocb_encrypt;
  c->dec = &sbdi_ocb_decrypt;
  c->mac = &sbdi_ocb_mac;
  *crypto = c;
  return SBDI_SUCCESS;
  FAIL: if (ae_ctx) {
    ae_clear(ae_ctx);
    ae_free(ae_ctx);
  }
  if (si_ctx) {
    memset(si_ctx, 0, sizeof(siv_ctx));
    free(si_ctx);
  }
  if (ocb_ctx) {
    free(ocb_ctx);
  }
  if (c) {
    free(c);
  }
  return r;
}

//----------------------------------------------------------------------
void sbdi_ocb_destroy(sbdi_crypto_t *crypto)
{
  if (crypto) {
    sbdi_ocb_ctx_t *ctx = (sbdi_ocb_ctx_t *) crypto->ctx;
    if (ctx) {
      if (ctx->ae_ctx) {
        ae_clear(ctx->ae_ctx);
        ae_free(ctx->ae_ctx);
      }
      if (ctx->siv_ctx) {
        memset(ctx->siv_ctx, 0, sizeof(siv_ctx));
        free(ctx->siv_ctx);
      }
    }
    free(crypto);
  }
}
