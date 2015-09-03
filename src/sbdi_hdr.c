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
/// \brief Manages Secure Block Device headers.
///
#include "sbdi_siv.h"
#include "sbdi_nocrypto.h"
#include "sbdi_ocb.h"
#include "sbdi_hmac.h"
#include "sbdi_hdr.h"
#include "sbdi_buffer.h"

#include "SecureBlockDeviceInterface.h"

#include <string.h>

//----------------------------------------------------------------------
void sbdi_hdr_v1_derive_key(siv_ctx *master, sbdi_hdr_v1_sym_key_t key,
    uint8_t *n1, size_t n1_len, uint8_t *n2, size_t n2_len)
{
  memset(key, 0, sizeof(sbdi_hdr_v1_sym_key_t));
  vprf(master, key, 1, n1, n1_len);
  vprf(master, key + SBDI_BLOCK_TAG_SIZE, 1, n2, n2_len);
}

/*!
 * \brief Determines if the given key type is supported by this header
 * library implementation
 *
 * @param type the key type to validate
 * @return true if the key type is supported (valid); false otherwise
 */
static inline int hdr_is_key_type_valid(const sbdi_hdr_v1_key_type_t type)
{
  return (type == SBDI_HDR_KEY_TYPE_NONE) || (type == SBDI_HDR_KEY_TYPE_OCB)
    || (type == SBDI_HDR_KEY_TYPE_SIV) || (type == SBDI_HDR_KEY_TYPE_HMAC);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_hdr_v1_create(sbdi_hdr_v1_t **hdr,
    const sbdi_hdr_v1_key_type_t type, const sbdi_hdr_v1_sym_key_t key)
{
  SBDI_CHK_PARAM(
      hdr && key && hdr_is_key_type_valid(type));
  sbdi_hdr_v1_t *h = calloc(1, sizeof(sbdi_hdr_v1_t));
  if (!h) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  memcpy(h->id.magic, SBDI_HDR_MAGIC, SBDI_HDR_MAGIC_LEN);
  h->id.version = SBDI_HDR_VERSION_1;
  sbdi_error_t r = sbdi_ctr_128b_init(&h->ctr, 0, 0);
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  h->type = type;
// Tag will be created once the header is written
// Copy previously created key into header
  memcpy(h->key, key, sizeof(sbdi_hdr_v1_sym_key_t));
  *hdr = h;
  return SBDI_SUCCESS;
}

void sbdi_hdr_v1_delete(sbdi_hdr_v1_t *hdr)
{
  if (!hdr) {
    return;
  }
  memset(hdr, 0, sizeof(sbdi_hdr_v1_t));
  free(hdr);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_hdr_v1_read(sbdi_t *sbdi, siv_ctx *master)
{
  SBDI_CHK_PARAM(sbdi && master);
  sbdi_hdr_v1_t *h = calloc(1, sizeof(sbdi_hdr_v1_t));
  if (!h) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  sbdi->write_store[0].idx = 0;
  uint32_t rd;
  sbdi_block_t *rd_buf = sbdi->write_store;
  sbdi_error_t r = sbdi_bl_read_block(sbdi, rd_buf, SBDI_BLOCK_SIZE, &rd);
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  sbdi_buffer_t b;
  sbdi_buffer_init(&b, *sbdi->write_store[0].data, SBDI_HDR_V1_PACKED_SIZE);
  sbdi_buffer_read_bytes(&b, h->id.magic, SBDI_HDR_MAGIC_LEN);
  if (memcmp(h->id.magic, SBDI_HDR_MAGIC, SBDI_HDR_MAGIC_LEN)) {
    free(h);
    return SBDI_ERR_ILLEGAL_STATE;
  }
  h->id.version = sbdi_buffer_read_uint32_t(&b);
  if (h->id.version > SBDI_HDR_SUPPORTED_VERSION) {
    free(h);
    return SBDI_ERR_UNSUPPORTED;
  }
  h->size = sbdi_buffer_read_uint64_t(&b);
  r = sbdi_buffer_read_ctr_128b(&b, &h->ctr);
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  h->type = sbdi_buffer_read_uint32_t(&b);
  if (!hdr_is_key_type_valid(h->type)) {
    free(h);
    return SBDI_ERR_UNSUPPORTED;
  }
  uint8_t *kptr = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_add_pos(&b, SBDI_HDR_V1_KEY_MAX_SIZE);
  sbdi_buffer_read_bytes(&b, h->tag, SBDI_HDR_V1_TAG_SIZE);
  int cr = siv_decrypt(master, kptr, h->key, SBDI_HDR_V1_KEY_MAX_SIZE, h->tag,
      0);
  if (cr == -1) {
    free(h);
    return SBDI_ERR_TAG_MISMATCH;
  }
  switch (h->type) {
  case SBDI_HDR_KEY_TYPE_NONE:
    r = sbdi_nocrypto_create(&sbdi->crypto, h->key);
    if (r != SBDI_SUCCESS) {
      free(h);
      return r;
    }
    break;
  case SBDI_HDR_KEY_TYPE_SIV:
    r = sbdi_siv_create(&sbdi->crypto, h->key);
    if (r != SBDI_SUCCESS) {
      // Cleanup of secret information must be handled by next layer up
      free(h);
      return r;
    }
    break;
  case SBDI_HDR_KEY_TYPE_OCB:
    r = sbdi_ocb_create(&sbdi->crypto, h->key);
    if (r != SBDI_SUCCESS) {
      // Cleanup of header SIV must be handled next layer up
      free(h);
      return r;
    }
    break;
  case SBDI_HDR_KEY_TYPE_HMAC:
    r = sbdi_hmac_create(&sbdi->crypto, h->key);
    if (r != SBDI_SUCCESS) {
      // Cleanup of header SIV must be handled next layer up
      free(h);
      return r;
    }
    break;
  default:
    free(h);
    return SBDI_ERR_UNSUPPORTED;
  }
  r = sbdi_bl_verify_header(sbdi, rd_buf);
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  sbdi->hdr = h;
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_hdr_v1_write(sbdi_t *sbdi, siv_ctx *master)
{
  SBDI_CHK_PARAM(sbdi);
  sbdi_hdr_v1_t *hdr = sbdi->hdr;
  uint8_t *wrt_buf = *sbdi->write_store[0].data;
  memset(wrt_buf, 0, SBDI_BLOCK_SIZE);
  sbdi_buffer_t b;
  sbdi->write_store[0].idx = 0;
  sbdi_buffer_init(&b, wrt_buf, SBDI_HDR_V1_PACKED_SIZE);
  sbdi_buffer_write_bytes(&b, hdr->id.magic, SBDI_HDR_MAGIC_LEN);
  sbdi_buffer_write_uint32_t(&b, hdr->id.version);
  sbdi_buffer_write_uint64_t(&b, hdr->size);
  sbdi_buffer_write_ctr_128b(&b, &hdr->ctr);
  sbdi_buffer_write_uint32_t(&b, hdr->type);
  uint8_t *kptr = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_add_pos(&b, SBDI_HDR_V1_KEY_MAX_SIZE);
  uint8_t *tptr = sbdi_buffer_get_cptr(&b);
  siv_encrypt(master, hdr->key, kptr, SBDI_HDR_V1_KEY_MAX_SIZE, tptr, 0);
  return sbdi_bl_write_hdr_block(sbdi, sbdi->write_store);
}

//----------------------------------------------------------------------
void sbdi_hdr_v1_update_size(sbdi_t *sbdi, const size_t size)
{
  sbdi->hdr->size = size;
}

//----------------------------------------------------------------------
uint64_t sbdi_hdr_v1_get_size(sbdi_t *sbdi)
{
  return (size_t) sbdi->hdr->size;
}
