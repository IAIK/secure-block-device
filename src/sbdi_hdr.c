/*
 * sbdi_hdr.c
 *
 *  Created on: May 30, 2014
 *      Author: dhein
 */

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

//----------------------------------------------------------------------
sbdi_error_t sbdi_hdr_v1_create(sbdi_hdr_v1_t **hdr,
    const sbdi_hdr_v1_sym_key_t key)
{
  SBDI_CHK_PARAM(hdr && key);
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
  // Copy previously created key into header
  memcpy(h->key, key, sizeof(sbdi_hdr_v1_sym_key_t));
  // counter scratch area init.
  sbdi_buffer_init(&h->ctr_buf, h->ctr_pkd, SBDI_CTR_128B_SIZE);
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
// TODO make sure all global counter values are packed in the same way!
  // TODO global counter not updated?
  r = sbdi_buffer_read_ctr_128b(&b, &h->ctr);
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  uint8_t *kptr = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_add_pos(&b, SBDI_HDR_V1_KEY_SIZE);
  sbdi_buffer_read_bytes(&b, h->tag, SBDI_HDR_V1_TAG_SIZE);
  int cr = siv_decrypt(master, kptr, h->key, SBDI_HDR_V1_KEY_SIZE, h->tag, 0);
  if (cr == -1) {
    free(h);
    return SBDI_ERR_TAG_MISMATCH;
  }
  // Header read init sbdi key context
  cr = siv_init(sbdi->ctx, h->key, SIV_256);
  if (cr == -1) {
    // Cleanup of secret information must be handled by next layer up
    free(h);
    return SBDI_ERR_CRYPTO_FAIL;
  }
  r = sbdi_bl_verify_header(sbdi, rd_buf);
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  // counter scratch area init.
  sbdi_buffer_init(&h->ctr_buf, h->ctr_pkd, SBDI_CTR_128B_SIZE);
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
  // TODO very strange buffer behavior the byte order is very much different
  // in the header than in the rest of the file ===> find out why!
  sbdi_buffer_write_ctr_128b(&b, &hdr->ctr);
  uint8_t *kptr = sbdi_buffer_get_cptr(&b);
  sbdi_buffer_add_pos(&b, SBDI_HDR_V1_KEY_SIZE);
  uint8_t *tptr = sbdi_buffer_get_cptr(&b);
  siv_encrypt(master, hdr->key, kptr, SBDI_HDR_V1_KEY_SIZE, tptr, 0);
  return sbdi_bl_write_hdr_block(sbdi, sbdi->write_store);
}

uint8_t *sbdi_hdr_v1_pack_ctr(sbdi_t *sbdi)
{
  sbdi_buffer_reset(&sbdi->hdr->ctr_buf);
  sbdi_buffer_write_ctr_128b(&sbdi->hdr->ctr_buf, &sbdi->hdr->ctr);
  return sbdi->hdr->ctr_pkd;
}
