/*
 * sbdi_block_layer.c
 *
 *  Created on: May 17, 2014
 *      Author: dhein
 */

#include "merkletree.h"
#include "siv.h"

#include "sbdi_config.h"
#include "sbdi_cache.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef struct secure_block_device_interface {
  int fd;
  siv_ctx *ctx;
  sbdi_bc_t *cache;
  mt_t *mt;
} sbdi_t;

typedef uint8_t sbdi_tag_t[SBDI_BLOCK_TAG_SIZE];

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_block(const sbdi_t *sbdi, sbdi_block_t block,
    uint32_t index, size_t len)
{
  if (!sbdi || !block || index > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ssize_t r = pread(sbdi->fd, block, len, index * SBDI_BLOCK_SIZE);
  if (r == -1) {
    return SBDI_ERR_IO;
  } else if (r < len) {
    return SBDI_ERR_MISSING_DATA;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_cache_decrypt(sbdi_t *sbdi, sbdi_block_t **blk,
    uint32_t blk_idx, size_t len, sbdi_tag_t *tag, int args_nbr, ...)
{
  // TODO check parameters!
  // args_nbr must be 1 or 2
  va_list args;
  va_start(args, args_nbr);
  unsigned char *ptrs[args_nbr];
  int lens[args_nbr];
  for (int i = 0; i < args_nbr; ++i) {
    ptrs[i] = (unsigned char *)va_arg(args, char*);
    lens[i] = va_arg(args, int);
  }
  va_end(args);
  sbdi_error_t r = sbdi_bc_cache_blk(sbdi->cache, blk_idx, blk);
  if (r != SBDI_SUCCESS) {
    return r;
  } else if (!(*blk)) {
    return SBDI_ERR_ILLEGAL_STATE;
  }
  r = sbdi_bl_read_block(sbdi, **blk, blk_idx, len);
  if (r != SBDI_SUCCESS) {
    // TODO free block reservation in cache!
    return r;
  }
  siv_restart(sbdi->ctx);
  if (args_nbr == 1) {
    if (!siv_decrypt(sbdi->ctx, **blk, **blk, SBDI_BLOCK_SIZE, *tag, args_nbr,
        ptrs[0], lens[0])) {
      // TODO free block reservation in cache!
      return SBDI_ERR_CRYPTO_FAIL;
    }
  } else if (args_nbr == 2) {
    if (!siv_decrypt(sbdi->ctx, **blk, **blk, SBDI_BLOCK_SIZE, *tag, args_nbr,
        ptrs[0], lens[0], ptrs[1], lens[1])) {
      // TODO free block reservation in cache!
      return SBDI_ERR_CRYPTO_FAIL;
    }
  } else {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_read_data_block(sbdi_t *sbdi, sbdi_block_t **block,
    uint32_t index, size_t len)
{
  if (!sbdi || !block || index > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE) {
    // TODO Question Johannes about 'deep' error checking (internal struct state)
    return SBDI_ERR_ILLEGAL_PARAM;
  }

  // TODO check that read is not beyond the bounds of file, otherwise the
  // Merkle tree won't work correctly!

  uint32_t mng_nbr = index / SBDI_MNGT_BLOCK_ENTRIES;
  uint32_t mng_idx = mng_nbr * SBDI_MNGT_BLOCK_ENTRIES;
  uint32_t dat_idx = index + mng_nbr + 2;
  uint32_t tag_idx = index % SBDI_MNGT_BLOCK_ENTRIES;

  sbdi_block_t *mngt;
  sbdi_error_t r;
  r = sbdi_bc_find_blk(sbdi->cache, mng_idx, &mngt);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  if (!mngt) {
    // Block not yet in cache
    r = sbdi_bc_cache_blk(sbdi->cache, mng_idx, &mngt);
    if (r != SBDI_SUCCESS) {
      return r;
    } else if (!mngt) {
      return SBDI_ERR_ILLEGAL_STATE;
    }
    r = sbdi_bl_read_block(sbdi, *mngt, mng_idx, SBDI_BLOCK_SIZE);
    if (r != SBDI_SUCCESS) {
      // TODO free block reservation in cache!
      return r;
    }
    sbdi_tag_t mng_tag;
    // Add block index as additional information to the decryption
    if (!siv_decrypt(sbdi->ctx, *mngt, *mngt, SBDI_BLOCK_SIZE, mng_tag, 1,
        &mng_idx, sizeof(uint32_t))) {
      // TODO free block reservation in cache!
      return SBDI_ERR_CRYPTO_FAIL;
    }
    // TODO add management tag to Merkle tree and validate root
    mt_error_t mt_r;
    mt_r = mt_verify(sbdi->mt, NULL, mng_nbr);
    if (mt_r != MT_SUCCESS) {
      // TODO better error code mapping?
      return SBDI_ERR_TAG_MISMATCH;
    }
  }
  r = sbdi_bc_find_blk(sbdi->cache, dat_idx, block);
  if (r != SBDI_SUCCESS) {
    return r;
  }
  unsigned char *blk_ctr = (*mngt) + tag_idx + SBDI_BLOCK_TAG_SIZE;
  if (!(*block)) {
    sbdi_tag_t tag;
    r = sbdi_bl_cache_decrypt(sbdi, block, dat_idx, len, &tag, 2, &dat_idx, sizeof(uint32_t), blk_ctr, SBDI_BLOCK_ACCESS_COUNTER_SIZE);
    if (r != SBDI_SUCCESS) {
      // TODO Cleanup?
      return r;
    }
    if (!memcmp(tag, &mngt[tag_idx], SBDI_BLOCK_TAG_SIZE)) {
      return SBDI_ERR_TAG_MISMATCH;
    } else {
      return SBDI_SUCCESS;
    }
  }
  return SBDI_SUCCESS;
}

