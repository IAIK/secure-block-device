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
#include "sbdi_ctr_128b.h"

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define SBDI_CACHE_SIZE ((SBDI_CACHE_MAX_SIZE)  * (SBDI_BLOCK_SIZE))

typedef struct secure_block_device_interface {
  int fd;
  siv_ctx *ctx;
  sbdi_bc_t *cache;
  mt_t *mt;
  sbdi_block_t write_store[2];
  sbdi_ctr_128b_t g_ctr;
} sbdi_t;

typedef uint8_t sbdi_tag_t[SBDI_BLOCK_TAG_SIZE];

//----------------------------------------------------------------------
sbdi_error_t sbdi_block_pair_init(sbdi_block_pair_t *pair, uint32_t mng_nbr,
    uint32_t mng_idx, uint32_t dat_idx, uint32_t tag_idx)
{
  if (!pair) {
    // TODO Additional error handling?
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  pair->mng_nbr = mng_nbr;
  pair->tag_idx = tag_idx;
  pair->mng = &pair->mng_dat;
  pair->blk = &pair->blk_dat;
  sbdi_block_init(pair->mng, mng_idx, NULL);
  sbdi_block_init(pair->blk, dat_idx, NULL);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len)
{
  if (!sbdi || !blk || !blk->data || blk->idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE || blk->data < sbdi->cache->store
      || blk->data > sbdi->cache->store + SBDI_CACHE_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ssize_t r = pread(sbdi->fd, blk->data, len, blk->idx * SBDI_BLOCK_SIZE);
  if (r == -1) {
    return SBDI_ERR_IO;
  } else if (r < len) {
    return SBDI_ERR_MISSING_DATA;
  }
  return SBDI_SUCCESS;
}

/*!
 * \brief converts a Merkle tree error into a secure block device interface
 * error
 *
 * @param mr the Merkle tree error code
 * @return the corresponding secure block device interface error code
 */
static inline sbdi_error_t bl_mt_sbdi_err_conv(mt_error_t mr)
{
  switch (mr) {
  case MT_SUCCESS:
    return SBDI_SUCCESS;
  case MT_ERR_OUT_Of_MEMORY:
    return SBDI_ERR_OUT_Of_MEMORY;
  case MT_ERR_ILLEGAL_PARAM:
    return SBDI_ERR_ILLEGAL_PARAM;
  case MT_ERR_ILLEGAL_STATE:
    return SBDI_ERR_ILLEGAL_STATE;
  case MT_ERR_ROOT_MISMATCH:
    return SBDI_ERR_TAG_MISMATCH;
  case MT_ERR_UNSPECIFIED:
    return SBDI_ERR_UNSPECIFIED;
  default:
    return SBDI_ERR_UNSUPPORTED;
  }
}

/*!
 * \brief Reads a block, decrypts the block, verifies decryption and puts the
 * decrypted block into cache.
 *
 * This function reads either a data or management block and puts the
 * decrypted data in the cache. For management blocks it passes the block tag
 * back to the calling function. For data blocks it verifies the tag and
 * returns SBDI_ERR_TAG_MISMATCH.
 *
 * This function works by reserving a block in the cache and then reading
 * data into the reserved block.
 *
 * @param sbdi[in] // TODO finish
 * @param blk[inout]
 * @param len[in]
 * @param tag[inout]
 * @param ctr[in]
 * @return
 */
static sbdi_error_t bl_cache_decrypt(sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len, uint8_t *tag, uint8_t *ctr)
{
  assert(
      sbdi && blk && sbdi_bc_is_valid(blk->idx) && len > 0 && len < SBDI_BLOCK_SIZE && tag);
  sbdi_bc_bt_t blk_type = (ctr) ? SBDI_BC_BT_DATA : SBDI_BC_BT_MNGT;
  SBDI_ERR_CHK(sbdi_bc_cache_blk(sbdi->cache, blk, blk_type));
  assert(blk->data);
  sbdi_error_t r = sbdi_bl_read_block(sbdi, blk, len);
  if (r != SBDI_SUCCESS) {
    sbdi_bc_evict_blk(sbdi->cache, blk->idx);
    return r;
  }
  int cr = -1;
  switch (blk_type) {
  case SBDI_BC_BT_MNGT:
    // Note: in case of a management block the tag is an out parameter,
    // because tag verification is done using the Merkle hash tree.
    // Note: Add block index as additional information to the decryption
    sbdi_siv_decrypt(sbdi->ctx, *blk->data, *blk->data, SBDI_BLOCK_SIZE, tag, 1,
        &blk->idx, sizeof(uint32_t));
    break;
  case SBDI_BC_BT_DATA:
    // Add block index and block counter as additional information to the decryption
    cr = siv_decrypt(sbdi->ctx, *blk->data, *blk->data, SBDI_BLOCK_SIZE, tag, 2,
        &blk->idx, sizeof(uint32_t), ctr, SBDI_BLOCK_CTR_SIZE);
    if (cr == -1) {
      sbdi_bc_evict_blk(sbdi->cache, blk->idx);
      return SBDI_ERR_TAG_MISMATCH;
    }
    break;
  default:
    sbdi_bc_evict_blk(sbdi->cache, blk->idx);
    return SBDI_ERR_ILLEGAL_STATE;
  }
  return SBDI_SUCCESS;
}

/*!
 * \brief Computes the memory address of a block tag with the specified index
 * relative to the given management block base address.
 * @param mng the management block that contains the memory base address
 * @param tag_idx the index of the block tag
 * @return the memory address of the block tag
 */
static inline uint8_t *bl_get_tag_address(sbdi_block_t *mng, uint32_t tag_idx)
{
  assert(mng && tag_idx < SBDI_MNGT_BLOCK_ENTRIES);
  return mng->data[tag_idx * (SBDI_BLOCK_TAG_SIZE + SBDI_BLOCK_CTR_SIZE)];
}

/*!
 * \brief Computes the memory address of a block counter with the specified
 * index relative to the given management block base address.
 * @param mng the management block that contains the memory base address
 * @param ctr_idx the index of the block counter
 * @return the memory address of the block counter
 */
static inline uint8_t *bl_get_ctr_address(sbdi_block_t *mng, uint32_t ctr_idx)
{
  assert(mng && ctr_idx < SBDI_MNGT_BLOCK_ENTRIES);
  return bl_get_tag_address(mng, ctr_idx) + SBDI_BLOCK_TAG_SIZE;
}

static sbdi_error_t bl_read_mngt_block(sbdi_t *sbdi, sbdi_block_t *mng,
    uint32_t mng_blk_nbr)
{
  sbdi_tag_t mng_tag;
  SBDI_ERR_CHK(bl_cache_decrypt(sbdi, mng, SBDI_BLOCK_SIZE, mng_tag, NULL));
  assert(mng->data);
  // TODO fix Merkle tree root hash check!

  SBDI_ERR_CHK(bl_mt_sbdi_err_conv(mt_verify(sbdi->mt, mng_tag, sizeof(sbdi_tag_t), mng_blk_nbr)));
  return SBDI_SUCCESS;
}

/*!
 * \brief TODO write documentation
 * @param sbdi
 * @param pair
 * @return
 */
static sbdi_error_t bl_read_data_block(sbdi_t *sbdi, sbdi_block_pair_t *pair)
{
  assert(sbdi && pair);
  // TODO assert internal state of the pair parameter
  SBDI_ERR_CHK(sbdi_bc_find_blk(sbdi->cache, pair->mng));
  if (!pair->mng->data) {
    // Management block not yet in cache
    SBDI_ERR_CHK(bl_read_mngt_block(sbdi, pair->mng, pair->mng_nbr));
  }
  SBDI_ERR_CHK(sbdi_bc_find_blk(sbdi->cache, pair->blk));
  if (!(pair->blk->data)) {
    // Data block not yet in cache
    uint8_t *ctr = bl_get_ctr_address(pair->mng, pair->tag_idx);
    uint8_t *tag = bl_get_tag_address(pair->mng, pair->tag_idx);
    SBDI_ERR_CHK(bl_cache_decrypt(sbdi, pair->blk, SBDI_BLOCK_SIZE, tag, ctr));
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t len)
{
  if (!sbdi || !ptr || idx > SBDI_BLOCK_MAX_INDEX || len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
// TODO check that read is not beyond the bounds of file, otherwise the
// Merkle tree won't work correctly!
  uint32_t mng_nbr = sbdi_get_mngt_block_number(idx);
  uint32_t mng_idx = sbdi_get_mngt_block_index(idx);
  uint32_t dat_idx = sbdi_get_data_block_index(idx);
  uint32_t tag_idx = sbdi_get_mngt_tag_index(idx);
  sbdi_block_pair_t pair;
  SBDI_ERR_CHK(sbdi_block_pair_init(&pair, mng_nbr, mng_idx, dat_idx, tag_idx));
  SBDI_ERR_CHK(bl_read_data_block(sbdi, &pair));
  // Copy data block from cache into target buffer
  memcpy(ptr, pair.blk->data, len);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_write_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len)
{
  if (!sbdi || !blk || !blk->data || blk->idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE || blk->data < sbdi->cache->store
      || blk->data > sbdi->cache->store + SBDI_CACHE_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ssize_t r = pwrite(sbdi->fd, blk->data, len, blk->idx * SBDI_BLOCK_SIZE);
  if (r == -1) {
    return SBDI_ERR_IO;
  } else if (r < len) {
    return SBDI_ERR_MISSING_DATA;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_write_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t len)
{
  if (!sbdi || !ptr || idx > SBDI_BLOCK_MAX_INDEX
      || len == 0|| len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
// TODO check that read is not beyond the bounds of file, otherwise the
// Merkle tree won't work correctly!
// TODO Think about caching behavior, when only one of the pair is in cache and is also the LRU.
  uint32_t mng_nbr = sbdi_get_mngt_block_number(idx);
  uint32_t mng_idx = sbdi_get_mngt_block_index(idx);
  uint32_t dat_idx = sbdi_get_data_block_index(idx);
  uint32_t tag_idx = sbdi_get_mngt_tag_index(idx);
  sbdi_block_pair_t pair;
  SBDI_ERR_CHK(sbdi_block_pair_init(&pair, mng_nbr, mng_idx, dat_idx, tag_idx));
  SBDI_ERR_CHK(bl_read_data_block(sbdi, &pair));
  memcpy(pair.blk->data, ptr, len);
// Nothing has of yet been written to the management block. This has to be
// done by the sync function, when the dependent data blocks are synced.
// Afterwards the management block should be written.
  SBDI_ERR_CHK(sbdi_bc_dirty_blk(sbdi->cache, pair.mng->idx));
  return sbdi_bc_dirty_blk(sbdi->cache, pair.blk->idx);
// Make sure block is in cache
// What I need to do:
// * Read Block into cache (done)
// * Get block access counter
// * Write to cache
// * Cache is synced later on
// * Write back new block access counter and tag to management block (also in cache)
}

static sbdi_error_t bl_encrypt_write_mngt(sbdi_t *sbdi, sbdi_block_t *mng)
{
  assert(sbdi && mng);
  assert(sizeof(sbdi_ctr_128b_t) == SBDI_BLOCK_CTR_SIZE);
  // TODO additional asserts?
  sbdi_tag_t mng_tag;
  // Assumption enforced by sbdi cache: All dependent data blocks are synced
  int cr = siv_encrypt(sbdi->ctx, *mng->data, *sbdi->write_store[0].data,
  SBDI_BLOCK_SIZE, mng_tag, 2, &mng->idx, sizeof(uint32_t), &sbdi->g_ctr,
  SBDI_BLOCK_CTR_SIZE);
  if (cr == -1) {
    return SBDI_ERR_CRYPTO_FAIL;
  }
  sbdi->write_store[0].idx = mng->idx;
  //sbdi->write_store[1].data = ;// TODO: Need to have actual store somewhere!
  SBDI_ERR_CHK(
      sbdi_bl_write_block(sbdi, &sbdi->write_store[0], SBDI_BLOCK_SIZE));
  return bl_mt_sbdi_err_conv(mt_update(sbdi->mt, mng_tag, sizeof(sbdi_tag_t), mng->idx));
}

static sbdi_error_t bl_encrypt_write_data(sbdi_t *sbdi, sbdi_block_t *blk)
{
  // encrypt block into write store using physical block index and the
  // global counter as additional headers
  sbdi_block_t mng;
  sbdi_tag_t data_tag;
  sbdi->write_store[0].idx = blk->idx;
  int cr = siv_encrypt(sbdi->ctx, *blk->data, *sbdi->write_store[0].data,
  SBDI_BLOCK_SIZE, data_tag, 2, &blk->idx, sizeof(uint32_t), &sbdi->g_ctr,
      sizeof(sbdi_ctr_128b_t));
  if (cr == -1) {
    return SBDI_ERR_CRYPTO_FAIL;
  }
  // Update tag and counter in management block
  mng.idx = sbdi_bl_idx_phy_to_mng(blk->idx);
  sbdi->write_store[1].idx = mng.idx;
  uint32_t mng_idx_pos = sbdi_bc_find_blk_idx_pos(sbdi->cache, mng.idx);
  if (!sbdi_bc_idx_is_valid(mng_idx_pos)) {
    // Management Block not found ==> IllegalState.
    return SBDI_ERR_ILLEGAL_STATE;
  }
  mng.data = sbdi_bc_get_db_for_cache_idx(sbdi->cache, mng_idx_pos);
  uint32_t tag_idx = sbdi_bl_idx_phy_to_log(blk->idx) % SBDI_MNGT_BLOCK_ENTRIES;
  memcpy(bl_get_tag_address(&mng, tag_idx), data_tag, SBDI_BLOCK_TAG_SIZE);
  memcpy(bl_get_ctr_address(&mng, tag_idx), &sbdi->g_ctr, SBDI_BLOCK_CTR_SIZE);
  sbdi_ctr_128b_inc(&sbdi->g_ctr);
  sbdi_tag_t mng_tag;
  // Management block updated now encrypt it
  cr = siv_encrypt(sbdi->ctx, *mng.data, *sbdi->write_store[1].data,
  SBDI_BLOCK_SIZE, mng_tag, 2, &blk->idx, sizeof(uint32_t));
  if (cr == -1) {
    return SBDI_ERR_CRYPTO_FAIL;
  }
  // TODO for the next three steps we need absolute consistency!
  sbdi_error_t r = sbdi_bl_write_block(sbdi, &sbdi->write_store[0],
  SBDI_BLOCK_SIZE);
  if (r != SBDI_SUCCESS) {
    // TODO additional error handing required!
    return r;
  }
  r = sbdi_bl_write_block(sbdi, &sbdi->write_store[1], SBDI_BLOCK_SIZE);
  if (r != SBDI_SUCCESS) {
    // TODO additional error handling required!
    return r;
  }
  // TODO Update Merkle Tree
  r = mt_update(sbdi->mt, mng_tag, sizeof(sbdi_tag_t), mng.idx);
  if (r != SBDI_SUCCESS) {
    // TODO additional error handling required!
    return r;
  }
  sbdi_bc_clear_blk_dirty(sbdi->cache, mng_idx_pos);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
static sbdi_error_t bl_sync(sbdi_t *sbdi, sbdi_block_t *blk)
{
  assert(sbdi && blk && blk->data && sbdi_bc_is_valid(blk->idx));
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(sbdi->cache, blk->idx);
  assert(
      sbdi_bc_idx_is_valid(idx_pos)
          && sbdi_bc_is_blk_dirty(sbdi->cache, idx_pos));
  switch (sbdi_bc_get_blk_type(sbdi->cache, idx_pos)) {
  case SBDI_BC_BT_MNGT:
    SBDI_ERR_CHK(bl_encrypt_write_mngt(sbdi, blk));
    break;
  case SBDI_BC_BT_DATA:
    SBDI_ERR_CHK(bl_encrypt_write_data(sbdi, blk));
    break;
  default:
    return SBDI_ERR_ILLEGAL_STATE;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_sync(void *sbdi, sbdi_block_t *blk)
{
  if (!sbdi || !blk || !blk->data || !sbdi_bc_is_valid(blk->idx)) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  return bl_sync((sbdi_t *) sbdi, blk);
}
