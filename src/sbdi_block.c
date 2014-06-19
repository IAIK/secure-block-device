/*
 * sbdi_block_layer.c
 *
 *  Created on: May 17, 2014
 *      Author: dhein
 */

#include "merkletree.h"
#include "sbdi_debug.h"
#include "sbdi_block.h"
#include "SecureBlockDeviceInterface.h"

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define SBDI_BL_ERR_IO_CHK(r, l) do { \
  if ((r) == -1) {                    \
    return SBDI_ERR_IO;               \
  } else if ((r) == 0) {              \
    return SBDI_ERR_IO_MISSING_BLOCK; \
  } else if ((r) < (l)) {             \
    return SBDI_ERR_IO_MISSING_DATA;  \
  }} while (0)

typedef struct sbdi_block_pair {
  sbdi_block_t blk_dat;
  sbdi_block_t mng_dat;
  sbdi_block_t *blk;
  sbdi_block_t *mng;
} sbdi_block_pair_t;

/*!
 * \brief Initializes an allocated block pair instance with the given
 * indices.
 * @param pair[inout] a pointer to the block pair type to initialize
 * @param mng_idx[in] the physical block index of the management block
 * @param dat_idx[in] the physical block index of the data block
 */
static inline void bl_pair_init(sbdi_block_pair_t *pair, uint32_t mng_idx,
    uint32_t dat_idx)
{
  assert(
      pair && sbdi_block_is_valid_phy(dat_idx)
          && sbdi_blic_is_phy_mng_blk(mng_idx));
  memset(pair, 0, sizeof(sbdi_block_pair_t));
  pair->mng = &pair->mng_dat;
  pair->blk = &pair->blk_dat;
  sbdi_block_init(pair->mng, mng_idx, NULL);
  sbdi_block_init(pair->blk, dat_idx, NULL);
}

/*!
 * \brief Computes the memory address of a block tag with the specified index
 * relative to the given management block base address.
 * @param mng[in] the management block that contains the memory base address
 * @param tag_idx[in] the index of the block tag
 * @return the memory address of the block tag
 */
static inline uint8_t *bl_get_tag_address(sbdi_block_t *mng, uint32_t tag_idx)
{
  assert(mng && tag_idx < SBDI_MNGT_BLOCK_ENTRIES);
  return *(mng->data) + (tag_idx * (SBDI_BLOCK_TAG_SIZE + SBDI_BLOCK_CTR_SIZE));
}

/*!
 * \brief Computes the memory address of a block counter with the specified
 * index relative to the given management block base address.
 * @param mng[in] the management block that contains the memory base address
 * @param ctr_idx[in] the index of the block counter
 * @return the memory address of the block counter
 */
static inline uint8_t *bl_get_ctr_address(sbdi_block_t *mng, uint32_t ctr_idx)
{
  assert(mng && ctr_idx < SBDI_MNGT_BLOCK_ENTRIES);
  return bl_get_tag_address(mng, ctr_idx) + SBDI_BLOCK_TAG_SIZE;
}

/*!
 * \brief Determines if the given pointer points into a valid memory region
 * to which the block read function may write
 *
 * @param sbdi[in] the secure block device interface that contains the valid
 * memory regions
 * @param mem[in] the memory pointer to check
 * @param len[in] the length of the data that will be written
 * @return true if the given memory pointer is a valid pointer for the block
 * read function to write to; false otherwise
 */
static int bl_is_valid_read_dest(const sbdi_t *sbdi, const uint8_t *mem,
    size_t len)
{
  const uint8_t *c_s = &sbdi->cache->store[0][0];
  const uint8_t *w_s = &sbdi->write_store_dat[0][0];
  int incache = mem >= c_s && mem <= c_s + SBDI_CACHE_SIZE - len;
  int instore = mem >= w_s && mem <= w_s + (2 * SBDI_BLOCK_SIZE) - len;
  return (incache || instore);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len, uint32_t *read)
{
  if (!sbdi || !blk || !blk->data
      || !sbdi_block_is_valid_phy(
          blk->idx) || len == 0|| len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  // Paranoia assertion
  assert(bl_is_valid_read_dest(sbdi, *blk->data, len));
  ssize_t r = sbdi->pio->pread(sbdi->pio->iod, blk->data, len,
      blk->idx * SBDI_BLOCK_SIZE);
  if (r != -1) {
    *read = r;
  }
  SBDI_BL_ERR_IO_CHK(r, len);
  return SBDI_SUCCESS;
}

/*!
 * \brief A wrapper to call AES CMAC on given management block.
 *
 * @param sbdi the secure block device interface to CMAC something for
 * (provides the key)
 * @param blk the data the CMAC should be computed for
 * @param tag the CMAC result tag
 * @return an error depending on the underlying mac implementation
 */
sbdi_error_t bl_aes_cmac(const sbdi_t *sbdi, const sbdi_block_t *blk,
    sbdi_tag_t tag)
{
  const int mlen = sizeof(sbdi_bl_data_t);
  sbdi_crypto_t *crypto = sbdi->crypto;
  const unsigned char *msg = *blk->data;
  sbdi_ctr_128b_t ctr;
  unsigned char *C = tag;

  // TODO Reactivate this sanity check!
  //assert(sizeof(sbdi_ctr_128b_t) == AES_BLOCK_SIZE);
  // I adapted the aes_cmac to add the block counter first. For this to work
  // I needed to pad the block index counter to a 16 byte block. Using the
  // 128 bit counter was the easiest way I could think of.
  sbdi_ctr_128b_init(&ctr, 0, blk->idx);
  //sbdi_error_t (void *ctx, const unsigned char *msg,
  //    const int mlen, unsigned char *C, const unsigned char *ad, const int ad_len);
  return crypto->mac(crypto->ctx, msg, mlen, C, (unsigned char *) &ctr,
      sizeof(sbdi_ctr_128b_t));
}

/*!
 * \brief Reads the content of a management block into memory, computes the
 * tag of the management block and adds it to the hash tree
 *
 * This function is essential for checking the integrity of the secure block
 * device interface, before it gets used. It reads the content of a single
 * management block (while bypassing the cache!), decrypts the management
 * block and adds the resulting tag to the Merkle tree.
 *
 * @param sbdi the secure block device interface to read the management block
 * from
 * @param phy_mng_idx the physical block index of the management block to
 * read
 * @param read the number of bytes read from the secure block device
 * interface; useful for checking a management block exists.
 * @return SBDI_SUCCESS if the block can be successfully read and added to
 * the Merkle tree; an SBDI_ERR_* error code otherwise.
 */
static sbdi_error_t bl_verify_mngt_block(sbdi_t *sbdi, uint32_t phy_mng_idx,
    uint32_t read)
{
  assert(sbdi_blic_is_phy_mng_blk(phy_mng_idx));
  sbdi_tag_t tag;
  memset(tag, 0, sizeof(tag));
  sbdi_block_t *mng = sbdi->write_store;
  mng->idx = phy_mng_idx;
  // Management block should always be fully readable.
  SBDI_ERR_CHK(sbdi_bl_read_block(sbdi, mng, SBDI_BLOCK_SIZE, &read));
  SBDI_ERR_CHK(bl_aes_cmac(sbdi, mng, tag));
  return sbdi_mt_sbdi_err_conv(mt_add(sbdi->mt, tag, sizeof(sbdi_tag_t)));
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_verify_block_layer(sbdi_t *sbdi, mt_hash_t root,
    uint32_t phy_last_blk_idx)
{
  if (!sbdi || !root) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (!phy_last_blk_idx) {
    // Empty or non existing or invalid file ==> nothing to do
    // TODO might want to change this once I have header handling and stuff
    return SBDI_SUCCESS;
  }
  // TODO Document that this function builds the hash tree, so that basic
  // hash tree update operations work, which is a requirement for every data
  // block write
  // TODO Should I check logical or physical indices for being to large?
  assert(sbdi_block_is_valid_phy(phy_last_blk_idx));
  // TODO next method is for logical index not physical fix that
  uint32_t mng_nbr = sbdi_blic_phy_to_mng_blk_nbr(phy_last_blk_idx);
  uint32_t read = 0;
  sbdi_error_t r = bl_verify_mngt_block(sbdi, 1, read);
  if (r == SBDI_ERR_IO_MISSING_BLOCK && read == 0) {
    // The first management block does not yet exist ==> no tree building
    // necessary
    return SBDI_SUCCESS;
  } else if (r != SBDI_SUCCESS) {
    return r;
  }
  for (int i = 1; i < (mng_nbr + 1); ++i) {
    uint32_t phy_mng = sbdi_blic_mng_blk_nbr_to_mng_phy(i);
    SBDI_ERR_CHK(bl_verify_mngt_block(sbdi, phy_mng, read));
  }
  mt_hash_t check_root;
  memset(check_root, 0, sizeof(mt_hash_t));
  SBDI_ERR_CHK(sbdi_mt_sbdi_err_conv(mt_get_root(sbdi->mt, check_root)));
  if (memcmp(root, check_root, sizeof(mt_hash_t))) {
    return SBDI_ERR_TAG_MISMATCH;
  }
  return SBDI_SUCCESS;
}

/*!
 * \brief Reads a data block, decrypts the data block, verifies decryption,
 * and puts the decrypted data block into cache.
 *
 * This function reads either a data block and decrypts it. If the
 * decryption MAC verification fails it returns SBDI_ERR_TAG_MISMATCH. If the
 * verification succeeds, the decrypted data is written to the cache.
 *
 * This function works by reserving a block in the cache and then reading
 * data into the reserved block. If reading the block fails at any point the
 * reserved cache segment gets invalidated.
 *
 * @param sbdi[in] the secure block device interface to work with
 * @param blk[inout] the block to decrypt and load into the cache
 * @param tag[in] the data block tag for verification
 * @param ctr[in] the access counter of a data block
 * @return SBDI_SUCCESS if the operation succeeds; otherwise
 * SBDI_ERR_TAG_MISMATCH if the tag verification of a data block fails; ...
 */
static sbdi_error_t bl_cache_decrypt(sbdi_t *sbdi, sbdi_block_t *blk,
    uint8_t *tag, uint8_t *ctr)
{
  assert(sbdi && blk && sbdi_block_is_valid_phy(blk->idx) && tag && ctr);
  SBDI_ERR_CHK(sbdi_bc_cache_blk(sbdi->cache, blk, SBDI_BC_BT_DATA));
  assert(blk->data);
  uint32_t read = 0;
  sbdi_error_t r = sbdi_bl_read_block(sbdi, blk, SBDI_BLOCK_SIZE, &read);
  if (r == SBDI_ERR_IO_MISSING_BLOCK && read == 0) {
    // Note: Block does not yet exist, create empty block.
    memset(*blk->data, 0, SBDI_BLOCK_SIZE);
    return SBDI_SUCCESS;
  } else if (r != SBDI_SUCCESS) {
    sbdi_bc_evict_blk(sbdi->cache, blk->idx);
    return r;
  }
  r = sbdi->crypto->dec(sbdi->crypto->ctx, *blk->data,
  SBDI_BLOCK_SIZE, ctr, blk->idx, *blk->data, tag);
  if (r != SBDI_SUCCESS) {
    // TODO what happens if sbdi_bc_evict_blk fails?
    sbdi_bc_evict_blk(sbdi->cache, blk->idx);
    return SBDI_ERR_TAG_MISMATCH;
  }
  return SBDI_SUCCESS;
}

static sbdi_error_t bl_read_mngt_block(sbdi_t *sbdi, sbdi_block_t *mng)
{
  assert(sbdi && mng && sbdi_blic_is_phy_mng_blk(mng->idx) && !mng->data);
  uint32_t read = 0;
  uint32_t mng_blk_nbr = sbdi_blic_phy_mng_to_mng_blk_nbr(mng->idx);
  sbdi_tag_t tag;
  memset(tag, 0, sizeof(sbdi_tag_t));
  SBDI_ERR_CHK(sbdi_bc_cache_blk(sbdi->cache, mng, SBDI_BC_BT_MNGT));
  assert(mng->data);
  sbdi_error_t r = sbdi_bl_read_block(sbdi, mng, SBDI_BLOCK_SIZE, &read);
  if (r != SBDI_SUCCESS) {
    sbdi_bc_evict_blk(sbdi->cache, mng->idx);
    return r;
  }
  r = bl_aes_cmac(sbdi, mng, tag);
  if (r != SBDI_SUCCESS) {
    sbdi_bc_evict_blk(sbdi->cache, mng->idx);
  }
  r = sbdi_mt_sbdi_err_conv(
      mt_verify(sbdi->mt, tag, sizeof(sbdi_tag_t), (mng_blk_nbr + 1)));
  if (r == SBDI_ERR_TAG_MISMATCH) {
    sbdi_bc_evict_blk(sbdi->cache, mng->idx);
  }
  return r;
}

static sbdi_error_t bl_read_data_block(sbdi_t *sbdi, sbdi_block_pair_t *pair,
    uint32_t tag_idx)
{
  assert(sbdi && pair);
  int do_bump_mng_blk = 0;
  SBDI_ERR_CHK(sbdi_bc_find_blk(sbdi->cache, pair->blk));
  if (!(pair->blk->data)) {
    SBDI_ERR_CHK(sbdi_bc_find_blk(sbdi->cache, pair->mng));
    if (!pair->mng->data) {
      // Management block not yet in cache
      SBDI_ERR_CHK(bl_read_mngt_block(sbdi, pair->mng));
      do_bump_mng_blk = 1;
    }
    // Data block not yet in cache
    uint8_t *ctr = bl_get_ctr_address(pair->mng, tag_idx);
    uint8_t *tag = bl_get_tag_address(pair->mng, tag_idx);
    SBDI_ERR_CHK(bl_cache_decrypt(sbdi, pair->blk, tag, ctr));
    /* Management block should stay in cache longer so make sure it gets the
     * LRU slot, instead of the data block! */
    if (do_bump_mng_blk) {
      // We just loaded the block, this simply must succeed!
      assert(sbdi_bc_find_blk(sbdi->cache, pair->mng) == SBDI_SUCCESS);
    }
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_read_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t off, size_t len)
{
  SBDI_CHK_PARAM(
      sbdi && ptr && sbdi_block_is_valid_log(idx) && off < SBDI_BLOCK_SIZE && len > 0 && len <= SBDI_BLOCK_SIZE && (off+len) <= SBDI_BLOCK_SIZE);
  uint32_t mng_idx = sbdi_blic_log_to_phy_mng_blk(idx);
  uint32_t dat_idx = sbdi_blic_log_to_phy_dat_blk(idx);
  uint32_t tag_idx = sbdi_blic_log_to_mng_tag_pos(idx);
  sbdi_block_pair_t pair;
  bl_pair_init(&pair, mng_idx, dat_idx);
  SBDI_ERR_CHK(bl_read_data_block(sbdi, &pair, tag_idx));
  // Copy data block from cache into target buffer
  memcpy(ptr, (*(pair.blk->data)) + off, len);
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_bl_verify_header(sbdi_t *sbdi, sbdi_block_t *hdr)
{
  SBDI_CHK_PARAM(sbdi && hdr && hdr->idx == 0 && hdr->data);
  sbdi_tag_t tag;
  memset(tag, 0, sizeof(sbdi_tag_t));
  SBDI_ERR_CHK(bl_aes_cmac(sbdi, hdr, tag));
  if (mt_al_get_size(sbdi->mt) == 0) {
    // TODO If the next line fails this is also really really bad!
    return sbdi_mt_sbdi_err_conv(mt_add(sbdi->mt, tag, sizeof(sbdi_tag_t)));
  } else {
    // TODO If the next line fails this is also really really bad!
    return sbdi_mt_sbdi_err_conv(
        mt_update(sbdi->mt, tag, sizeof(sbdi_tag_t), 0));
  }
}

/*!
 * \brief Determines if the given pointer points into a valid memory region
 * from which the block write function may read
 *
 * @param sbdi[in] the secure block device interface that contains the valid
 * memory regions
 * @param mem[in] the memory pointer to check
 * @param len[in] the length of the data that will be read
 * @return true if the given memory pointer is a valid pointer for the block
 * write function to read from; false otherwise
 */
static int bl_is_valid_write_source(const sbdi_t *sbdi, const uint8_t *mem,
    size_t len)
{
  const uint8_t *c_s = &sbdi->cache->store[0][0];
  const uint8_t *w_s = &sbdi->write_store_dat[0][0];
  int incache = mem >= c_s && mem <= c_s + (SBDI_CACHE_SIZE) - len;
  // Management block may only be written from block 0
  // TODO do I still need write store[1] now that I can directly write
  // management blocks from cache?
  int instore = mem >= w_s && mem <= w_s + (SBDI_BLOCK_SIZE) - len;
  return incache || instore;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_write_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len)
{
  if (!sbdi || !blk || !blk->data
      || !sbdi_block_is_valid_phy(
          blk->idx)|| len == 0|| len > SBDI_BLOCK_SIZE) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  assert(bl_is_valid_write_source(sbdi, *blk->data, SBDI_BLOCK_SIZE));
  ssize_t r = sbdi->pio->pwrite(sbdi->pio->iod, blk->data, len,
      blk->idx * SBDI_BLOCK_SIZE);
  SBDI_BL_ERR_IO_CHK(r, len);
  return SBDI_SUCCESS;

}

/*!
 * \brief MACs and writes a specific management block to the data store.
 *
 * @param sbdi[in] the secure block data interface instance to use for
 * writing the block
 * @param mng[in] the management block to write
 * @param mng_tag[out] the tag of the management block that is computed for
 * encryption
 * @return SBDI_SUCCESS if encrypting and writing the data block succeeds; an
 * error generated by sbdi_bl_write_block otherwise
 */
static sbdi_error_t bl_mac_write_mngt(sbdi_t *sbdi, sbdi_block_t *mng,
    sbdi_tag_t mng_tag)
{
  assert(sbdi && mng);
  assert(sizeof(sbdi_ctr_128b_t) == SBDI_BLOCK_CTR_SIZE);
  SBDI_ERR_CHK(bl_aes_cmac(sbdi, mng, mng_tag));
  // TODO if this gets only partially written then there is a big problem!
  // TODO I do not need to write the whole block, just the updated part is
  // sufficient
  return sbdi_bl_write_block(sbdi, mng, SBDI_BLOCK_SIZE);
}

/*!
 * \brief Creates all management blocks with a physical index less than the
 * physical index of l
 *
 * This function is used if a new block that did not previously exist is
 * written. It makes sure that all management blocks are in-place so that
 * the merkle tree works.
 *
 * @param sbdi the secure block data interface instance of which to extend
 * the data store
 * @param log the logical index of a data block
 * @return SBDI_SUCCESS if the operation succeeds, some SBDI_ERR_* otherwise
 */
static sbdi_error_t bl_ensure_mngt_blocks_exist(sbdi_t *sbdi, uint32_t log)
{
  sbdi_tag_t mng_tag;
  memset(mng_tag, 0, sizeof(sbdi_tag_t));
  // Clear write buffer
  memset(sbdi->write_store[0].data, 0, SBDI_BLOCK_SIZE);
  uint32_t mng_blk_nbr = sbdi_blic_log_to_mng_blk_nbr(log) + 1;
  uint32_t s = mt_get_size(sbdi->mt);
  assert(s > 0); // There must always be the header block present!
  s -= 1; // Deduct header block
  while (s < mng_blk_nbr) {
    sbdi->write_store[0].idx = sbdi_blic_mng_blk_nbr_to_mng_phy(s);
    sbdi_buffer_t b;
    sbdi_buffer_init(&b, *sbdi->write_store[0].data, SBDI_BLOCK_CTR_SIZE);
    // TODO do I need a better nonce than the current global counter?
    sbdi_buffer_write_ctr_128b(&b, &sbdi->hdr->ctr);
    sbdi_ctr_128b_inc(&sbdi->hdr->ctr);
    SBDI_ERR_CHK(bl_mac_write_mngt(sbdi, &sbdi->write_store[0], mng_tag));
    SBDI_ERR_CHK(
        sbdi_mt_sbdi_err_conv(mt_add(sbdi->mt, mng_tag, sizeof(sbdi_tag_t))));
    s += 1;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_write_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t off, size_t len)
{
  SBDI_CHK_PARAM(
      sbdi && ptr && sbdi_block_is_valid_log(idx) && off < SBDI_BLOCK_SIZE && len > 0 && len <= SBDI_BLOCK_SIZE && off + len <= SBDI_BLOCK_SIZE);
  SBDI_ERR_CHK(bl_ensure_mngt_blocks_exist(sbdi, idx));
  // TODO Think about caching behavior, when only one of the pair is in cache and is also the LRU.
  uint32_t mng_idx = sbdi_blic_log_to_phy_mng_blk(idx);
  uint32_t dat_idx = sbdi_blic_log_to_phy_dat_blk(idx);
  uint32_t tag_idx = sbdi_blic_log_to_mng_tag_pos(idx);
  sbdi_block_pair_t pair;
  bl_pair_init(&pair, mng_idx, dat_idx);
  SBDI_ERR_CHK(bl_read_data_block(sbdi, &pair, tag_idx));
  memcpy((*(pair.blk->data)) + off, ptr, len);
// Nothing has of yet been written to the management block. This has to be
// done by the sync function, when the dependent data blocks are synced.
// Afterwards the management block should be written.
  return sbdi_bc_dirty_blk(sbdi->cache, pair.blk->idx);
// Make sure block is in cache
// What I need to do:
// * Read Block into cache (done)
// * Get block access counter
// * Write to cache
// * Cache is synced later on
// * Write back new block access counter and tag to management block (also in cache)
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_bl_write_hdr_block(sbdi_t *sbdi, sbdi_block_t *hdr)
{
  sbdi_tag_t tag;
  // TODO memset tag!
  SBDI_CHK_PARAM(sbdi && hdr && hdr->idx == 0 && hdr->data);
  SBDI_ERR_CHK(bl_aes_cmac(sbdi, hdr, tag));
  SBDI_ERR_CHK(sbdi_bl_write_block(sbdi, hdr, SBDI_BLOCK_SIZE));
  // TODO r < BLOCK_SIZE is really really bad => incompletely written header!
  if (mt_al_get_size(sbdi->mt) == 0) {
    // TODO If the next line fails this is also really really bad!
    return sbdi_mt_sbdi_err_conv(mt_add(sbdi->mt, tag, sizeof(sbdi_tag_t)));
  } else {
    // TODO If the next line fails this is also really really bad!
    return sbdi_mt_sbdi_err_conv(
        mt_update(sbdi->mt, tag, sizeof(sbdi_tag_t), 0));
  }
}

static sbdi_error_t bl_encrypt_write_update_mngt(sbdi_t *sbdi,
    sbdi_block_t *mng)
{
  sbdi_tag_t mng_tag;
  memset(mng_tag, 0, sizeof(sbdi_tag_t));
  // TODO I need a test vector that actually triggers this path
  SBDI_ERR_CHK(bl_mac_write_mngt(sbdi, mng, mng_tag));
  return sbdi_mt_sbdi_err_conv(
      mt_update(sbdi->mt, mng_tag, sizeof(sbdi_tag_t),
          (sbdi_blic_phy_mng_to_mng_blk_nbr(mng->idx) + 1)));
}

static inline void bl_update_mng_blk(sbdi_block_t *mng, uint32_t idx,
    sbdi_ctr_128b_t *ctr, sbdi_tag_t tag)
{
  // TODO Use data buffer for this?
  unsigned char *tag_addr = bl_get_tag_address(mng, idx);
  unsigned char *ctr_addr = bl_get_ctr_address(mng, idx);

  memcpy(tag_addr, tag, SBDI_BLOCK_TAG_SIZE);

  sbdi_buffer_t b;
  // TODO should I move memset into init, or remove memset?
  memset(&b, 0, sizeof(sbdi_buffer_t));
  sbdi_buffer_init(&b, ctr_addr, SBDI_BLOCK_CTR_SIZE);
  sbdi_buffer_write_ctr_128b(&b, ctr);

  sbdi_ctr_128b_inc(ctr);
}

static sbdi_error_t bl_encrypt_write_data(sbdi_t *sbdi, sbdi_block_t *blk)
{
  sbdi_block_t mng;
  sbdi_tag_t data_tag;
  memset(data_tag, 0, sizeof(sbdi_tag_t));
  sbdi->write_store[0].idx = blk->idx;
  SBDI_ERR_CHK(
      sbdi->crypto->enc(sbdi->crypto->ctx, *blk->data, SBDI_BLOCK_SIZE, &sbdi->hdr->ctr, blk->idx, *sbdi->write_store[0].data, data_tag));
  // Update tag and counter in management block
  mng.idx = sbdi_blic_phy_dat_to_phy_mng_blk(blk->idx);
  sbdi->write_store[1].idx = mng.idx;
  uint32_t mng_idx_pos = sbdi_bc_find_blk_idx_pos(sbdi->cache, mng.idx);
  if (!sbdi_bc_idx_is_valid(mng_idx_pos)) {
    // Management Block not found ==> IllegalState.
    return SBDI_ERR_ILLEGAL_STATE;
  }
  mng.data = sbdi_bc_get_db_for_cache_idx(sbdi->cache, mng_idx_pos);
  uint32_t tag_idx = sbdi_blic_phy_dat_to_log(
      blk->idx) % SBDI_MNGT_BLOCK_ENTRIES;
  bl_update_mng_blk(&mng, tag_idx, &sbdi->hdr->ctr, data_tag);
  sbdi_tag_t mng_tag;
  memset(mng_tag, 0, sizeof(sbdi_tag_t));
  // TODO check if write store[1] still needed
  // TODO for the next four steps we need absolute consistency!
  // Management block updated now encrypt it
  SBDI_ERR_CHK(bl_aes_cmac(sbdi, &mng, mng_tag));
  sbdi_error_t r = sbdi_bl_write_block(sbdi, &sbdi->write_store[0],
  SBDI_BLOCK_SIZE);
  if (r != SBDI_SUCCESS) {
    // TODO additional error handing required!
    return r;
  }
  r = sbdi_bl_write_block(sbdi, &mng, SBDI_BLOCK_SIZE);
  if (r != SBDI_SUCCESS) {
    // TODO additional error handling required!
    return r;
  }
  // Management Index for Merkle tree needs to be logical index
  r = mt_update(sbdi->mt, mng_tag, sizeof(sbdi_tag_t),
      (sbdi_blic_phy_mng_to_mng_blk_nbr(mng.idx) + 1));
  if (r != SBDI_SUCCESS) {
    // TODO additional error handling required!
    return r;
  }
  // TODO problem if mngt block still dirty from other dependent block
  sbdi_bc_clear_blk_dirty(sbdi->cache, mng_idx_pos);
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
static sbdi_error_t bl_sync(sbdi_t *sbdi, sbdi_block_t *blk)
{
  assert(sbdi && blk && blk->data && sbdi_block_is_valid_phy(blk->idx));
  uint32_t idx_pos = sbdi_bc_find_blk_idx_pos(sbdi->cache, blk->idx);
  assert(sbdi_bc_is_elem_valid_and_dirty(sbdi->cache, idx_pos));
  switch (sbdi_bc_get_blk_type(sbdi->cache, idx_pos)) {
  case SBDI_BC_BT_MNGT:
    assert(sbdi_blic_is_phy_mng_blk(blk->idx));
    SBDI_ERR_CHK(bl_encrypt_write_update_mngt(sbdi, blk));
    break;
  case SBDI_BC_BT_DATA:
    assert(sbdi_blic_is_phy_dat_blk(blk->idx));
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
  SBDI_CHK_PARAM(sbdi && blk && blk->data && sbdi_block_is_valid_phy(blk->idx));
  sbdi_t *t_sbdi = (sbdi_t *) sbdi;
  SBDI_DBG(sbdi_dbg_print_delim());
  SBDI_DBG(sbdi_dbg_print_block(blk));
  SBDI_DBG(sbdi_dbg_print_cache_idx(t_sbdi->cache));
  return bl_sync(t_sbdi, blk);
}
