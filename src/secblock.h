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
#include <stdlib.h>

#define SBDI_HDR_VERSION_1 1
#define SBDI_HDR_MAGIC_LEN 8

#define SBDI_HDR_SUPPORTED_VERSION SBDI_HDR_VERSION_1

#define SBDI_HDR_KS_ALG_AES 0x00000001
#define SBDI_HDR_KS_ALG_RSA 0x80000001

#define SBDI_HDR_V1_TAG_LEN 16
#define SBDI_HDR_V1_KS0_ADDR 0x100
#define SBDI_HDR_V1_KS0_KEY_SIZE 32
#define SBDI_HDR_V1_KS_MAX_KEY_SIZE 512

typedef uint8_t sbdi_magic_t[SBDI_HDR_MAGIC_LEN];
typedef uint8_t sbdi_sym_key_t[SBDI_HDR_V1_KS0_KEY_SIZE];
typedef uint8_t sbdi_tag_t[SBDI_HDR_V1_TAG_LEN];

static const sbdi_magic_t SBDI_MAGIC = {
    0xA1, 0x1D, 0x1F, 0xDE, 0xAD, 0xDA, 0x7A, 0xFF
};

static const uint8_t sbdi_siv_master_key[32] = {
    0xa7, 0xde, 0x2e, 0xb8, 0xf7, 0xc2, 0x85, 0xa6,
    0x66, 0x27, 0x9c, 0xa4, 0x8e, 0x4c, 0xb5, 0xda,
    0x98, 0xaf, 0x8c, 0x50, 0x5d, 0xe6, 0x4a, 0xf0,
    0x29, 0x87, 0x6e, 0x34, 0x4c, 0x0b, 0x9b, 0x5a
};

/*!
 * TODO Description
 */
typedef struct secure_block_device_interface_key_slot {
	uint8_t  key_uuid[16]; /*!< the universal unique id based key identifier */
	uint32_t key_alg_id;   /*!< an identifier for the algorithm used to encrypt the block device key */
	uint32_t key_size;     /*!< the length of the encrypted blob of secure block device key blob */
} sbdi_ks_t;

/*!
 * TODO Description
 */
typedef struct secure_block_device_interface_header {
  sbdi_magic_t magic;
	uint32_t version;
	sbdi_ctr_128b_t ctr;
	uint8_t  tag[SBDI_HDR_V1_TAG_LEN];
	sbdi_ks_t key_slots[8];
} sbdi_hdr_t;

int sbdi_open(void);
ssize_t sbdi_pread(int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t sbdi_pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);
void sbdi_close(int filedes);

#endif /* SECBLOCK_H_ */

#ifdef __cplusplus
}
#endif
