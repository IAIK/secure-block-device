/*
 * secblock.c
 *
 *  Created on: May 13, 2014
 *      Author: dhein
 */

#include "secblock.h"

#include <string.h>
#include <stdio.h>

//----------------------------------------------------------------------
sbdi_error_t sbdi_create_hdr(sbdi_hdr_t **hdr)
{
  if (!hdr) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_hdr_t *lhdr = calloc(1, sizeof(sbdi_hdr_t));
  if (!lhdr) {
    return SBDI_ERR_OUT_Of_MEMORY;
  }
  lhdr->version = SBDI_HDR_VERSION_1;
  *hdr = lhdr;
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
static sbdi_error_t sbdi_check_hdr(sbdi_hdr_t *hdr)
{
  if (hdr == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (hdr->version != 1) {
    return SBDI_ERR_UNSUPPORTED;
  }
  printf("Nbr. of key slots: %lx", sizeof(hdr->key_slots));
  if (hdr->key_slots[0].key_alg_id != SBDI_HDR_KS_ALG_AES) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (hdr->key_slots[0].key_size != SBDI_HDR_V1_KS0_KEY_SIZE) {
    return SBDI_ERR_UNSUPPORTED;
  }
  for (int i = 1; i < sizeof(hdr->key_slots); ++i) {
//    // Make sure only supported algorithms are present
//    // This check might be softened up to if not used ==> don't care
//    if (hdr->key_slots[i].key_alg_id != SBDI_HDR_KS_ALG_AES ||
//        hdr->key_slots[i].key_alg_id != SBDI_HDR_KS_ALG_RSA) {
//      return SBDI_ERR_UNSUPPORTED;
//    }
    if (hdr->key_slots[i].key_size > SBDI_HDR_V1_KS_MAX_KEY_SIZE) {
      return SBDI_ERR_UNSUPPORTED;
    }
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
int sbdi_open(void)
{
//  int fd;
  sbdi_error_t err;
  sbdi_hdr_t *hdr = NULL;
//  err = sdbi_fb_open(&fd);
//  if (err != SBDI_SUCCESS) {
//    // TODO Set error flag?
//    return -1;
//  }
//  err = sbdi_fb_read_hdr(fd, &hdr);
//  if (err != SBDI_SUCCESS) {
//    // TODO Set error flag?
//    return -1;
//  }
  err = sbdi_check_hdr(hdr);
  if (err != SBDI_SUCCESS) {
    // TODO Set error flag?
    return -1;
  }
  return 0;
}
