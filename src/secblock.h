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

#include "sbdi_err.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

#define SBDI_HDR_VERSION_1 1

#define SBDI_HDR_SUPPORTED_VERSION SBDI_HDR_VERSION_1

#define SBDI_HDR_KS_ALG_AES 0x00000001
#define SBDI_HDR_KS_ALG_RSA 0x80000001

#define SBDI_HDR_V1_KS0_KEY_SIZE 16
#define SBDI_HDR_V1_KS_MAX_KEY_SIZE 512

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
	uint32_t version;
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
