/*
 * sbdi_file_backend.c
 *
 *  Created on: May 13, 2014
 *      Author: dhein
 */

#include "secblock.h"
#include "siv.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

//----------------------------------------------------------------------
sbdi_error_t sdbi_fb_open(int *fd)
{
  if (fd == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  *fd = open("sbdi_fb.raw", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (*fd == -1) {
    return SBDI_ERR_IO;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_read_block(const int fd, sbdi_block_t block,
    uint32_t index, size_t len)
{
  if (fd
      == -1|| block == NULL || index > MAX_BLOCKS || len == 0 || len > BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ssize_t r = pread(fd, block, len, index * BLOCK_SIZE);
  if (r == -1) {
    return SBDI_ERR_IO;
  } else if (r < len) {
    return SBDI_ERR_MISSING_DATA;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_read_data_block(const int fd, sbdi_block_t block,
    uint32_t index, size_t len)
{
  if (fd
      == -1|| block == NULL || index > MAX_BLOCKS || len == 0 || len > BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }

  uint32_t tag_block_off = ((index / MNGT_BLOCK_ENTRIES) + 1);
  uint32_t enc_idx = index + 1 + tag_block_off;
  uint32_t mng_idx = (index / MNGT_BLOCK_ENTRIES) * MNGT_BLOCK_ENTRIES;
  uint32_t tag_idx = index % MNGT_BLOCK_ENTRIES;

  // TODO put block management into a caching layer
  sbdi_block_t mngt;
  sbdi_error_t res;
  res = sbdi_fb_read_block(fd, mngt, mng_idx, BLOCK_SIZE);
  if (res != SBDI_SUCCESS) {
    return res;
  }
  res = sbdi_fb_read_block(fd, block, enc_idx, len);
  if (res != SBDI_SUCCESS) {
    return res;
  }
  // TODO more intelligent crypto handling
  siv_ctx ctx;
  sbdi_tag_t mng_tag;
  sbdi_tag_t blk_tag;
  siv_init(&ctx, sbdi_siv_master_key, SBDI_HDR_V1_KS0_KEY_SIZE);
  siv_decrypt(&ctx, mngt, mngt, BLOCK_SIZE, mng_tag, 0);
  // TODO Integrate Merkle tree
  siv_restart(&ctx);
  siv_decrypt(&ctx, block, block, len, blk_tag, 1, &mngt[tag_idx+SBDI_HDR_V1_TAG_LEN], CTR_LENGTH);
  if (!memcmp(blk_tag, &mngt[tag_idx], SBDI_HDR_V1_TAG_LEN)) {
    return SBDI_ERR_TAG_MISMATCH;
  } else {
    return SBDI_SUCCESS;
  }

}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_write_block(const int fd, const sbdi_block_t *block,
    uint32_t index, size_t len)
{
  if (fd
      == -1|| block == NULL || index > MAX_BLOCKS || len == 0 || len > BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ssize_t w = pwrite(fd, &block, len, index * BLOCK_SIZE);
  if (w == -1) {
    return SBDI_ERR_IO;
  } else if (w < len) {
    return SBDI_ERR_MISSING_DATA;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_write_data_block(const int fd, const sbdi_block_t *block,
    uint32_t index, size_t len)
{
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_read_hdr(const int fd, sbdi_hdr_t **hdr)
{
  if (fd == -1 || hdr == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  sbdi_block_t hdr_blk;
  sbdi_error_t res;
  siv_ctx ctx;
  uint8_t tag[SBDI_HDR_V1_TAG_LEN];
  memset(hdr_blk, 0xFF, sizeof(hdr_blk));
  res = sbdi_fb_read_block(fd, hdr_blk, 0, BLOCK_SIZE);
  if (res != SBDI_SUCCESS) {
    return res;
  }
  sbdi_hdr_t *h = (sbdi_hdr_t *) hdr_blk;
  if (h->version > SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (h->version == SBDI_HDR_VERSION_1) {
    h = malloc(sizeof(sbdi_hdr_t));
    if (!h) {
      return SBDI_ERR_OUT_Of_MEMORY;
    }
    memcpy(h, hdr_blk, sizeof(sbdi_hdr_t));
    *hdr = h;
    siv_init(&ctx, sbdi_siv_master_key, 32);
    // TODO Pack the header, as to be sure of its structure and then
    // directly calculate the offset without using sizeof
    size_t prefix_len = (sizeof(sbdi_magic_t) + sizeof(uint32_t)
        + sizeof(sbdi_ctr_128b_t));
    size_t infix_offs = prefix_len + SBDI_HDR_V1_TAG_LEN;
    size_t infix_len = SBDI_HDR_V1_KS0_ADDR - infix_offs;
    siv_decrypt(&ctx, &hdr_blk[SBDI_HDR_V1_KS0_ADDR],
        &hdr_blk[SBDI_HDR_V1_KS0_ADDR], SBDI_HDR_V1_KS0_KEY_SIZE, tag, 3,
        hdr_blk, prefix_len, &hdr_blk[infix_offs], infix_len,
        &hdr_blk[SBDI_HDR_V1_KS0_ADDR + SBDI_HDR_V1_KS0_KEY_SIZE],
        BLOCK_SIZE - (SBDI_HDR_V1_KS0_ADDR + SBDI_HDR_V1_KS0_KEY_SIZE));
    if (!memcmp(tag, h->tag, SBDI_HDR_V1_TAG_LEN)) {
      return SBDI_SUCCESS;
    } else {
      return SBDI_ERR_TAG_MISMATCH;
    }
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_write_hdr(const int fd, const sbdi_hdr_t *hdr)
{
  if (fd == -1 || hdr == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (hdr->version < SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (hdr->version == SBDI_HDR_VERSION_1) {
    ssize_t r = pwrite(fd, hdr, sizeof(sbdi_hdr_t), 0);
    if (r == -1) {
      return SBDI_ERR_IO;
    } else if (r < sizeof(sbdi_hdr_t)) {
      return SBDI_ERR_MISSING_DATA;
    }
    return SBDI_SUCCESS;
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_read_key(const int fd, const sbdi_hdr_t *hdr,
    const uint32_t slot, uint8_t **key_blob)
{
  if (fd == -1 || hdr == NULL || slot > 7 || key_blob == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (hdr->version < SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (hdr->version == SBDI_HDR_VERSION_1) {
    size_t key_offset = 0;
    size_t blob_size = 0;
    if (slot == 0) {
      key_offset = 0x0100;
      blob_size = 0x10;
    } else {
      key_offset = 0x0200 * slot;
      blob_size = hdr->key_slots[slot].key_size;
    }
    uint8_t *kb = malloc(blob_size);
    if (!kb) {
      return SBDI_ERR_OUT_Of_MEMORY;
    }
    int r = pread(fd, kb, blob_size, key_offset);
    if (r == -1) {
      free(kb);
      return SBDI_ERR_IO;
    } else if (r < blob_size) {
      free(kb);
      return SBDI_ERR_MISSING_DATA;
    }
    *key_blob = kb;
    return SBDI_SUCCESS;
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_write_key(const int fd, sbdi_hdr_t *hdr,
    const uint32_t slot, uint8_t *key_blob)
{
  if (fd == -1 || hdr == NULL || slot > 7 || key_blob == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (hdr->version < SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (hdr->version == SBDI_HDR_VERSION_1) {
    size_t key_offset = 0;
    size_t blob_size = 0;
    if (slot == 0) {
      key_offset = 0x0100;
      blob_size = 0x10;
    } else {
      key_offset = 0x0200 * slot;
      blob_size = hdr->key_slots[slot].key_size;
    }
    int r = pwrite(fd, key_blob, blob_size, key_offset);
    if (r == -1) {
      return SBDI_ERR_IO;
    } else if (r < blob_size) {
      return SBDI_ERR_MISSING_DATA;
    }
    return SBDI_SUCCESS;
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
void sbdi_fb_free_hdr(sbdi_hdr_t *hdr)
{
  free(hdr);
}

//----------------------------------------------------------------------
void sbdi_fb_free_key_blob(uint8_t *key_blob)
{
  free(key_blob);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_close(int fd)
{
  int r = close(fd);
  if (r == -1) {
    return SBDI_ERR_IO;
  }
  return SBDI_SUCCESS;
}
