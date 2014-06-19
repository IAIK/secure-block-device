/*
 * SecureBlockDeviceInterface.h
 *
 *  Created on: May 12, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SECURE_BLOCK_DEVICE_INTERFACE_H_
#define SECURE_BLOCK_DEVICE_INTERFACE_H_

#include "sbdi_config.h"
#include "sbdi_pio.h"
#include "sbdi_crypto.h"
#include "sbdi_cache.h"
#include "sbdi_ctr_128b.h"
#include "sbdi_block.h"
#include "sbdi_hdr.h"
#include "sbdi_crypto_type.h"

#include <sys/types.h>
#include <stdint.h>

/*!
 * \brief converts a Merkle tree error into a secure block device interface
 * error
 *
 * @param mr the Merkle tree error code
 * @return the corresponding secure block device interface error code
 */
static inline sbdi_error_t sbdi_mt_sbdi_err_conv(mt_error_t mr)
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

typedef uint8_t sbdi_sym_mst_key_t[32];

// TODO remove
static const sbdi_sym_mst_key_t sbdi_siv_master_key = { 0xa7, 0xde, 0x2e, 0xb8,
    0xf7, 0xc2, 0x85, 0xa6, 0x66, 0x27, 0x9c, 0xa4, 0x8e, 0x4c, 0xb5, 0xda,
    0x98, 0xaf, 0x8c, 0x50, 0x5d, 0xe6, 0x4a, 0xf0, 0x29, 0x87, 0x6e, 0x34,
    0x4c, 0x0b, 0x9b, 0x5a };

/*!
 * \brief enumeration type for defining the values of
 * TODO: Do I need this?
 */
typedef enum sbdi_whence {
  SBDI_SEEK_SET = 1, //!< SBDI_SEEK_SET
  SBDI_SEEK_CUR = 2, //!< SBDI_SEEK_CUR
  SBDI_SEEK_END = 3 //!< SBDI_SEEK_END
} sbdi_whence_t;

struct secure_block_device_interface {
  sbdi_pio_t *pio;
  sbdi_crypto_t *crypto;
  void *mt;
  sbdi_hdr_v1_t *hdr;
  sbdi_bc_t *cache;
  sbdi_bl_data_t write_store_dat[2];
  sbdi_block_t write_store[2];
  size_t offset;
};

// TODO remove later
sbdi_t *sbdi_create(sbdi_pio_t *pioypto);
void sbdi_delete(sbdi_t *sbdi);

sbdi_error_t sbdi_open(sbdi_t **s, sbdi_pio_t *pio, sbdi_crypto_type_t ct, sbdi_sym_mst_key_t mkey,
    mt_hash_t root);
sbdi_error_t sbdi_close(sbdi_t *sbdi, sbdi_sym_mst_key_t mkey, mt_hash_t root);

sbdi_error_t sbdi_pread(ssize_t *rd, sbdi_t *sbdi, void *buf, size_t nbyte,
    off_t offset);
sbdi_error_t sbdi_pwrite(ssize_t *wr, sbdi_t *sbdi, const void *buf,
    size_t nbyte, off_t offset);

sbdi_error_t sbdi_read(ssize_t *rd, sbdi_t *sbdi, void *buf, size_t nbyte);
sbdi_error_t sbdi_write(ssize_t *wr, sbdi_t *sbdi, const void *buf,
    size_t nbyte);

sbdi_error_t sbdi_lseek(off_t *new_off, sbdi_t *sbdi, off_t offset,
    sbdi_whence_t whence);

sbdi_error_t sbdi_fsync(sbdi_t *sbdi, sbdi_sym_mst_key_t mkey);

#endif /* SECURE_BLOCK_DEVICE_INTERFACE_H_ */

#ifdef __cplusplus
}
#endif
