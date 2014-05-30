/*
 * secblock.c
 *
 *  Created on: May 13, 2014
 *      Author: dhein
 */

#include "siv.h"

#include "secblock.h"
#include "sbdi_block.h"
#include "sbdi_buffer.h"

#include <string.h>

//----------------------------------------------------------------------
void sbdi_derive_hdr_v1_key(siv_ctx *master, sbdi_hdr_v1_sym_key_t key,
    uint8_t *n1, size_t n1_len, uint8_t *n2, size_t n2_len)
{
  memset(key, 0, sizeof(sbdi_hdr_v1_sym_key_t));
  vprf(master, key, 1, n1, n1_len);
  vprf(master, key + SBDI_BLOCK_TAG_SIZE, 1, n2, n2_len);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_create_hdr_v1(sbdi_hdr_v1_t **hdr, sbdi_hdr_v1_sym_key_t key)
{
  SBDI_CHK_PARAM(hdr);
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
  // Tag will be created once the header is written
  memset(h->tag, 0, sizeof(sbdi_tag_t));
  // Copy previously created key into header
  memcpy(h->key, key, sizeof(sbdi_hdr_v1_sym_key_t));
  *hdr = h;
  return SBDI_SUCCESS;
}

void sbdi_delete_hdr_v1(sbdi_hdr_v1_t *hdr)
{
// This should remove traces of the key from memory
// TODO do the same for the SBDI data structure
  memset(hdr, 0, sizeof(sbdi_hdr_v1_t));
  free(hdr);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_read_hdr_v1(sbdi_t *sbdi, sbdi_hdr_v1_t **hdr,
    siv_ctx *master)
{
  SBDI_CHK_PARAM(sbdi && hdr);

  sbdi_hdr_v1_t *h = calloc(1, sizeof(sbdi_hdr_v1_t));
  if (!h) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  sbdi_bl_read_hdr_block(sbdi, *sbdi->write_store[0].data,
  SBDI_HDR_V1_PACKED_SIZE);
  sbdi_buffer_t b;
  sbdi_buffer_init(&b, *sbdi->write_store[0].data, SBDI_HDR_V1_PACKED_SIZE);
  sbdi_buffer_read_bytes(&b, h->id.magic, SBDI_HDR_MAGIC_LEN);
  if (!memcmp(h->id.magic, SBDI_HDR_MAGIC, SBDI_HDR_MAGIC_LEN)) {
    free(h);
    return SBDI_ERR_ILLEGAL_STATE;
  }
  h->id.version = sbdi_buffer_read_uint32_t(&b);
  if (h->id.version > SBDI_HDR_SUPPORTED_VERSION) {
    free(h);
    return SBDI_ERR_UNSUPPORTED;
  }
// TODO make sure all global counter values are packed in the same way!
  sbdi_error_t r = sbdi_buffer_read_ctr_128b(&b, &h->ctr);
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  uint8_t *kptr = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_add_pos(&b, SBDI_HDR_V1_KEY_SIZE);
  sbdi_buffer_read_bytes(&b, h->tag, SBDI_HDR_V1_TAG_SIZE);
//  int cr = siv_init(&ctx, sbdi_siv_master_key, SIV_256);
//  if (cr == -1) {
//    free(h);
//    return SBDI_ERR_CRYPTO_FAIL;
//  }
  int cr = siv_decrypt(master, kptr, h->key, SBDI_HDR_V1_KEY_SIZE, h->tag, 0);
  if (cr == -1) {
    free(h);
    return SBDI_ERR_TAG_MISMATCH;
  }
  *hdr = h;
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_write_hdr_v1(const sbdi_t *sbdi, const sbdi_hdr_v1_t *hdr,
    siv_ctx *master)
{
  SBDI_CHK_PARAM(sbdi && hdr);
  sbdi_buffer_t b;
  sbdi_buffer_init(&b, *sbdi->write_store[0].data, SBDI_HDR_V1_PACKED_SIZE);
  sbdi_buffer_write_bytes(&b, hdr->id.magic, SBDI_HDR_MAGIC_LEN);
  sbdi_buffer_write_uint32_t(&b, hdr->id.version);
  sbdi_buffer_write_ctr_128b(&b, &hdr->ctr);
  uint8_t *kptr = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_add_pos(&b, SBDI_HDR_V1_KEY_SIZE);
  uint8_t *tptr = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_add_pos(&b, SBDI_HDR_V1_TAG_SIZE);
  siv_encrypt(master, hdr->key, kptr, SBDI_HDR_V1_KEY_SIZE, tptr, 0);
// TODO actually write header somewhere!
  return SBDI_SUCCESS;
}
