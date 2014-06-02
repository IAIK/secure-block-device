/*
 * secblock.c
 *
 *  Created on: May 13, 2014
 *      Author: dhein
 */

#include "siv.h"

#include "SecureBlockDeviceInterface.h"

#include <string.h>

static inline void sbdi_init(sbdi_t *sbdi, sbdi_pio_t *pio, siv_ctx *ctx,
    mt_t *mt, sbdi_bc_t *cache)
{
  assert(sbdi && ctx && mt && cache);
  memset(sbdi, 0, sizeof(sbdi_t));
  sbdi->pio = pio;
  sbdi->ctx = ctx;
  sbdi->mt = mt;
  sbdi->cache = cache;
  sbdi->write_store[0].data = &sbdi->write_store_dat[0];
  sbdi->write_store[1].data = &sbdi->write_store_dat[1];
}

//----------------------------------------------------------------------
sbdi_t *sbdi_create(sbdi_pio_t *pio)
{
  sbdi_t *sbdi = calloc(1, sizeof(sbdi_t));
  if (!sbdi) {
    return NULL;
  }
  siv_ctx *ctx = calloc(1, sizeof(siv_ctx));
  if (!ctx) {
    free(sbdi);
    return NULL;
  }
  mt_t *mt = mt_create();
  if (!mt) {
    free(ctx);
    free(sbdi);
    return NULL;
  }
  sbdi_bc_t *cache = sbdi_bc_cache_create(&sbdi_bl_sync, sbdi);
  if (!cache) {
    mt_delete(mt);
    free(ctx);
    free(sbdi);
    return NULL;
  }
  sbdi_init(sbdi, pio, ctx, mt, cache);
  return sbdi;
}

//----------------------------------------------------------------------
void sbdi_delete(sbdi_t *sbdi)
{
  if (!sbdi) {
    return;
  }
  sbdi_bc_cache_destroy(sbdi->cache);
  mt_delete(sbdi->mt);
  // Overwrite key material
  memset(sbdi->ctx, 0, sizeof(siv_ctx));
  free(sbdi->ctx);
  // Overwrite header if present
  sbdi_hdr_v1_delete(sbdi->hdr);
  memset(sbdi, 0, sizeof(sbdi_t));
  free(sbdi);
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_open(sbdi_t **s, sbdi_pio_t *pio, sbdi_sym_mst_key_t mkey,
    mt_hash_t root)
{
  // TODO what about root? Can be null, but only ...
  SBDI_CHK_PARAM(s && pio && mkey);
  // variables that need explicit cleaning
  siv_ctx mctx;
  memset(&mctx, 0, sizeof(siv_ctx));
  sbdi_hdr_v1_sym_key_t key;
  memset(&key, 0, sizeof(sbdi_hdr_v1_sym_key_t));
  sbdi_error_t r = SBDI_ERR_UNSPECIFIED;
  // Start body of function
  int cr = siv_init(&mctx, mkey, SIV_256);
  if (cr == -1) {
    r = SBDI_ERR_CRYPTO_FAIL;
    goto FAIL;
  }
  sbdi_t *sbdi = sbdi_create(pio);
  r = sbdi_hdr_v1_read(sbdi, &mctx);
  if (r == SBDI_ERR_IO_MISSING_BLOCK) {
    // Empty block device ==> create header
    // TODO find a better way to provide nonce material
    const char *n1 = "nonce1";
    const char *n2 = "nonce2";
    sbdi_hdr_v1_derive_key(&mctx, key, (uint8_t*) n1, strlen(n1), (uint8_t*) n2,
        strlen(n2));
    cr = siv_init(sbdi->ctx, key, SIV_256);
    if (cr == -1) {
      r = SBDI_ERR_CRYPTO_FAIL;
      goto FAIL;
    }
    r = sbdi_hdr_v1_create(&sbdi->hdr, key);
    if (r != SBDI_SUCCESS) {
      goto FAIL;
    }
    r = sbdi_hdr_v1_write(sbdi, &mctx);
    if (r != SBDI_SUCCESS) {
      // TODO this is really bad and needs good error handling
      goto FAIL;
    }
    *s = sbdi;
    return SBDI_SUCCESS;
  } else if (r != SBDI_SUCCESS) {
    goto FAIL;
  }
  sbdi_bl_verify_block_layer(sbdi, root, pio->size_at_open / SBDI_BLOCK_SIZE);
  *s = sbdi;
  return SBDI_SUCCESS;

  FAIL: memset(&mctx, 0, sizeof(siv_ctx));
  memset(key, 0, sizeof(sbdi_hdr_v1_sym_key_t));
  sbdi_delete(sbdi);
  return r;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_close(sbdi_t *sbdi, sbdi_sym_mst_key_t mkey, mt_hash_t root)
{
  SBDI_CHK_PARAM(sbdi && mkey && root);
  siv_ctx mctx;
  memset(&mctx, 0, sizeof(siv_ctx));
  sbdi_error_t r = SBDI_ERR_UNSPECIFIED;
  int cr = siv_init(&mctx, mkey, SIV_256);
  if (cr == -1) {
    r = SBDI_ERR_CRYPTO_FAIL;
    goto FAIL;
  }
  r = sbdi_hdr_v1_write(sbdi, &mctx);
  if (r != SBDI_SUCCESS) {
    // TODO very bad, potentially partially written header!
    goto FAIL;
  }
  r = sbdi_bc_sync(sbdi->cache);
  if (r != SBDI_SUCCESS) {
    // TODO very bad, potentially inconsistent state!
    goto FAIL;
  }
  r = sbdi_mt_sbdi_err_conv(mt_get_root(sbdi->mt, root));
  if (r != SBDI_SUCCESS) {
    // this should not happen, because it should have failed earlier
    goto FAIL;
  }
  sbdi_delete(sbdi);
  return SBDI_SUCCESS;

  FAIL: memset(&mctx, 0, sizeof(siv_ctx));
  return r;
}

#define SBDI_MIN(A, B) ((A) > (B))?(B):(A)

/*!
 * \brief computes the minimum of the two given size_t values
 *
 * @param a the first input size_t value
 * @param b the second input size_t value
 * @return the minimum of a and b
 */
static inline size_t size_min(size_t a, size_t b)
{
  return SBDI_MIN(a, b);
}

/*!
 * \brief Checks if an addition of the two size_t parameters is overflow safe
 *
 * @param a[in] the first size_t parameter to check
 * @param b[in] the second size_t parameter to check
 * @return true if the addition is overflow safe; false otherwise
 */
static inline int os_add_size(const size_t a, const size_t b)
{
  return (a + b) >= size_min(a, b);
}

/*!
 * \brief Checks if an addition of the two uint32_t parameters is overflow
 * safe
 *
 * @param a[in] the first uint32_t parameter to check
 * @param b[in] the second uint32_t parameter to check
 * @return true if the addition is overflow safe; false otherwise
 */
static inline int os_add_uint32(const uint32_t a, const uint32_t b)
{
  return (a + b) >= SBDI_MIN(a, b);
}

/*
 * The following macros are taken from:
 * Catching Integer Overflows in C
 * http://www.fefe.de/intof.html
 */
#define __HALF_MAX_SIGNED(type) ((type)1 << (sizeof(type)*8-2))
#define __MAX_SIGNED(type) (__HALF_MAX_SIGNED(type) - 1 + __HALF_MAX_SIGNED(type))
#define __MIN_SIGNED(type) (-1 - __MAX_SIGNED(type))

#define __MIN(type) ((type)-1 < 1?__MIN_SIGNED(type):(type)0)
#define __MAX(type) ((type)~__MIN(type))

/*!
 * \brief Tests if the given off_t can be safely added to the given size_t
 *
 * This function checks if it is safe to add the given off_t b to the given
 * size_t a. Safe here means that the addition will not lead to an integer
 * overflow. If b is positive normal unsigned integer overflow checks apply.
 * If b is negative the function ensures the a + (-b) >= 0. Finally, this
 * function also checks if the result of the addition fits into an off_t
 * type.
 *
 * @param a[in] the size_t value to add to b
 * @param b[in] the off_t value to add to a
 * @return SBDI_SUCCESS if the two values can be added safely;
 *         SBDI_ERR_ILLEGAL_PARAM otherwise
 */
static inline sbdi_error_t os_add_off_size(const size_t a, const off_t b)
{
  // TODO put this assertions and other of its kind into an initializer
  assert(sizeof(size_t) == sizeof(off_t));
  if (b < 0) {
    // Integer overflow possible
    size_t min_abs;
    // (l)(l)abs(__MIN(off_t) is potentially not defined take care of this
    if (b == __MIN(off_t)) {
      min_abs = ((size_t) __MAX(off_t)) + 1;
    } else {
      min_abs = (-1 * b);
    }
    SBDI_CHK_PARAM(min_abs > a);
  } else {
    // Both are positive ==> treat as unsigned integer overflow problem
    SBDI_CHK_PARAM(os_add_size(a, (size_t )b));
  }
  // Finally this checks if the result of the addition fits into an offset
  // type. TODO: this should map to an EOVERFLOW error instead of EINVAL -
  // use a different error code?
  SBDI_CHK_PARAM(a + b <= __MAX(off_t));
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_pread(ssize_t *rd, sbdi_t *sbdi, void *buf, size_t nbyte,
    off_t offset)
{
  SBDI_CHK_PARAM(rd && sbdi && buf);
  // Make sure offset is non-negative and less than or equal to the max sbd size
  SBDI_CHK_PARAM(offset >= 0 && offset <= SBDI_SIZE_MAX);
  // TODO: Put this and others of its kind into an initializer
  assert(sizeof(size_t) == sizeof(off_t));
//  SBDI_CHK_PARAM(__MAX(off_t) <= SBDI_SIZE_MAX);
  // nbyte > ssize_t ==> impl. defined
  SBDI_CHK_PARAM(nbyte <= __MAX(off_t));
  if (nbyte == 0) {
    *rd = 0;
    return SBDI_SUCCESS;
  }
  uint8_t *ptr = buf;
  size_t rlen = nbyte;
  size_t sbdi_size = sbdi_hdr_v1_get_size(sbdi);
  // Check if this will start reading beyond the secure block device
  if (offset >= sbdi_size) {
    *rd = 0;
    return SBDI_SUCCESS;
  }
  // We already asserted that the offset is positive ==> check if it will
  // overflow on addition using unsigned integer overflow check!
  SBDI_CHK_PARAM(os_add_size((size_t )offset, nbyte));
  if (offset + nbyte > sbdi_size) {
    // Reduce the amount of bytes read to the amount that is currently there
    // In in multi-threading environment this will lead to race conditions if
    // sbdi_pread, sbdi_read, sbdi_pwrite, sbdi_write are not properly
    // synchronized! TODO (ensure this!)
    rlen -= ((offset + nbyte) - sbdi_size);
  }
  // TODO handle case where read would be beyond max SBD size
  // This is indirectly already handled
  // determine number of first block
  uint32_t idx = offset / SBDI_BLOCK_SIZE;
  *rd = 0;
  while (rlen) {
    size_t to_read = (rlen > SBDI_BLOCK_SIZE) ? SBDI_BLOCK_SIZE : rlen;
    SBDI_ERR_CHK(sbdi_bl_read_data_block(sbdi, ptr, idx, to_read));
    *rd += to_read;
    rlen -= to_read;
    ptr += to_read;
    assert(os_add_uint32(idx, 1));
    idx += 1;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_pwrite(ssize_t *wr, sbdi_t *sbdi, const void *buf,
    size_t nbyte, off_t offset)
{
  SBDI_CHK_PARAM(wr && sbdi && buf);
  // Make sure offset is non-negative and less than or equal to the max SBD size
  SBDI_CHK_PARAM(offset >= 0 && offset <= SBDI_SIZE_MAX);
  // TODO: Put this and others of its kind into an initializer
  assert(sizeof(size_t) == sizeof(off_t));
//  SBDI_CHK_PARAM(__MAX(off_t) <= SBDI_SIZE_MAX);
  // nbyte > ssize_t ==> impl. defined ==> fail
  SBDI_CHK_PARAM(nbyte <= __MAX(off_t));
  if (nbyte == 0) {
    *wr = 0;
    return SBDI_SUCCESS;
  }
  uint8_t *ptr = (uint8_t *) buf;
  size_t rlen = nbyte;
  SBDI_CHK_PARAM(os_add_size((size_t )offset, nbyte));
  if ((offset + nbyte) > SBDI_SIZE_MAX) {
    // Function ensures offset less than SBDI_SIZE_MAX
    rlen = SBDI_SIZE_MAX - offset;
  }
  // determine number of first block
  uint32_t idx = offset / SBDI_BLOCK_SIZE;
  *wr = 0;
  while (rlen) {
    size_t to_write = (rlen > SBDI_BLOCK_SIZE) ? SBDI_BLOCK_SIZE : rlen;
    SBDI_ERR_CHK(sbdi_bl_write_data_block(sbdi, ptr, idx, to_write));
    *wr += to_write;
    rlen -= to_write;
    ptr += to_write;
    assert(os_add_uint32(idx, 1));
    idx += 1;
  }
  return SBDI_SUCCESS;
}

sbdi_error_t sbdi_lseek(off_t *new_off, sbdi_t *sbdi, off_t offset,
    sbdi_whence_t whence)
{
  SBDI_CHK_PARAM(new_off && sbdi && offset < SBDI_SIZE_MAX);
  size_t sbdi_size = sbdi_hdr_v1_get_size(sbdi);
  switch (whence) {
  case SBDI_SEEK_SET:
    // Disallow setting the offset to a negative number
    SBDI_CHK_PARAM(offset >= 0);
    sbdi->offset = offset;
    *new_off = sbdi->offset;
    return SBDI_SUCCESS;
  case SBDI_SEEK_CUR:
    // TODO write test case to test overflow protection
    SBDI_ERR_CHK(os_add_off_size(sbdi->offset, offset));
    sbdi->offset += offset;
    *new_off = sbdi->offset;
    return SBDI_SUCCESS;
  case SBDI_SEEK_END:
    // TODO write test case to test overflow protection
    SBDI_ERR_CHK(os_add_off_size(sbdi_size, offset));
    sbdi->offset = sbdi_size + offset;
    *new_off = sbdi->offset;
    return SBDI_SUCCESS;
  default:
    return SBDI_ERR_ILLEGAL_PARAM;
  }
}

sbdi_error_t sbdi_read(ssize_t *rd, sbdi_t *sbdi, void *buf, size_t nbyte)
{
  sbdi_error_t r = sbdi_pread(rd, sbdi, buf, nbyte, sbdi->offset);
  if (r != SBDI_SUCCESS && *rd == 0) {
    return r;
  }
  SBDI_ERR_CHK(os_add_off_size(sbdi->offset, *rd));
  sbdi->offset += *rd;
  return r;
}

sbdi_error_t sbdi_write(ssize_t *wr, sbdi_t *sbdi, const void *buf,
    size_t nbyte) {
  sbdi_error_t r = sbdi_pwrite(wr, sbdi, buf, nbyte, sbdi->offset);
  if (r != SBDI_SUCCESS && *wr == 0) {
    return r;
  }
  SBDI_ERR_CHK(os_add_off_size(sbdi->offset, *wr));
  sbdi->offset += *wr;
  return r;
}
