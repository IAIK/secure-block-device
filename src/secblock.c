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
sbdi_error_t sbdi_create_hdr_v1(sbdi_hdr_v1_t **hdr)
{
  SBDI_CHK_PARAM(hdr);
  sbdi_hdr_v1_t *h = calloc(1, sizeof(sbdi_hdr_v1_t));
  if (!h) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  memcpy(h->id.magic, SBDI_HDR_MAGIC, SBDI_HDR_MAGIC_LEN);
  h->id.version = SBDI_HDR_VERSION_1;
  sbdi_ctr_128b_init(&h->ctr, 0, 0);
  // TODO set key, set tag
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
sbdi_error_t sbdi_read_hdr_v1(sbdi_t *sbdi, sbdi_hdr_v1_t **hdr)
{
  SBDI_CHK_PARAM(sbdi && hdr);
  siv_ctx ctx;

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
  // TODO write buffer extensions to read global counter and keys
  // TODO make sure all global counter values are packed in the same way!
  sbdi_error_t r = sbdi_ctr_128b_init(&h->ctr, sbdi_buffer_read_uint64_t(&b),
      sbdi_buffer_read_uint64_t(&b));
  if (r != SBDI_SUCCESS) {
    free(h);
    return r;
  }
  sbdi_buffer_read_bytes(&b, h->tag, sizeof(sbdi_tag_t));
  sbdi_buffer_read_bytes(&b, h->key, SBDI_HDR_V1_KEY_SIZE);
  int cr = siv_init(&ctx, sbdi_siv_master_key, SIV_256);
  if (cr == -1) {
    free(h);
    return SBDI_ERR_CRYPTO_FAIL;
  }
  cr = siv_decrypt(&ctx, h->key, h->key, SBDI_HDR_V1_KEY_SIZE, h->tag, 0);
  if (cr == -1) {
    free(h);
    return SBDI_ERR_TAG_MISMATCH;
  }
  *hdr = h;
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_write_hdr_v1(sbdi_t *sbdi, sbdi_hdr_v1_t *hdr)
{
  SBDI_CHK_PARAM(sbdi && hdr);
  siv_ctx ctx;
  sbdi_buffer_t b;
  sbdi_buffer_init(b, *sbdi->write_store[0].data, SBDI_HDR_V1_PACKED_SIZE);
  sbdi_buffer_write_bytes(&b, hdr->id.magic, SBDI_HDR_MAGIC_LEN);
  sbdi_buffer_write_uint32_t(&b, hdr->id.version);
  sbdi_buffer_write_uint64_t(&b, hdr->ctr.hi);
  sbdi_buffer_write_uint64_t(&b, hdr->ctr.lo);
  int cr = siv_init(&ctx, sbdi_siv_master_key, SIV_256);
  if (cr == -1) {
    return SBDI_ERR_CRYPTO_FAIL;
  }
  sbdi_tag_t tag;
  // TODO do I really want to encrypt the key in the header when it gets written
  // out?
  siv_encrypt(&ctx, hdr->key, hdr->key, SBDI_HDR_V1_KEY_SIZE, tag, 0);
  sbdi_buffer_write_bytes(&b, tag, sizeof(sbdi_tag_t));
  sbdi_buffer_write_bytes(&b, hdr->key, SBDI_HDR_V1_KEY_SIZE);
  // TODO actually write header somewhere!
  return SBDI_SUCCESS;
}
