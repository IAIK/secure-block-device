/*
 * secblock.h
 *
 *  Created on: May 12, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SECBLOCK_H_
#define SECBLOCK_H_

#include "sbdi_config.h"
#include "sbdi_ctr_128b.h"

#include <sys/types.h>
#include <stdint.h>

#define SBDI_HDR_VERSION_1 1u
#define SBDI_HDR_MAGIC_LEN 8u

#define SBDI_HDR_SUPPORTED_VERSION SBDI_HDR_VERSION_1

#define SBDI_HDR_V1_PACKED_SIZE 76u
#define SBDI_HDR_V1_KEY_SIZE    32u
#define SBDI_HDR_V1_TAG_SIZE    SBDI_BLOCK_TAG_SIZE

typedef uint8_t sbdi_hdr_magic_t[SBDI_HDR_MAGIC_LEN];
typedef uint8_t sbdi_hdr_v1_sym_key_t[SBDI_HDR_V1_KEY_SIZE];

static const sbdi_hdr_magic_t SBDI_HDR_MAGIC = {
    0xA1, 0x1D, 0x1F, 0xDE, 0xAD, 0xDA, 0x7A, 0xFF
};

static const uint8_t sbdi_siv_master_key[SBDI_HDR_V1_KEY_SIZE] = {
    0xa7, 0xde, 0x2e, 0xb8, 0xf7, 0xc2, 0x85, 0xa6,
    0x66, 0x27, 0x9c, 0xa4, 0x8e, 0x4c, 0xb5, 0xda,
    0x98, 0xaf, 0x8c, 0x50, 0x5d, 0xe6, 0x4a, 0xf0,
    0x29, 0x87, 0x6e, 0x34, 0x4c, 0x0b, 0x9b, 0x5a
};

/*!
 * \brief holds the information necessary to identify a secure block device
 * interface header and its version
 */
typedef struct secure_block_device_interface_header_id {
  sbdi_hdr_magic_t magic; //!< the magic number identifying a secure block device interface
  uint32_t version; //!< the version of the secure block device interface header
} sbdi_hdr_id_t;

/*!
 * \brief the secure block device interface header
 */
typedef struct secure_block_device_interface_header_v1 {
  sbdi_hdr_id_t id; //!< the secure block device interface identification information
	sbdi_ctr_128b_t ctr; //!< access counter protecting the header against replay attacks
	sbdi_tag_t tag; //!< the tag protecting the integrity of the key
	sbdi_hdr_v1_sym_key_t key; //!< the encrypted secure block device key
} sbdi_hdr_v1_t;

int sbdi_open(void);
ssize_t sbdi_pread(int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t sbdi_pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);
void sbdi_close(int filedes);

#endif /* SECBLOCK_H_ */

#ifdef __cplusplus
}
#endif
