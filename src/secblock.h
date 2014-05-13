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

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

/*!
 * TODO Description
 */
typedef struct secure_block_device_interface_key_slot {
	uint32_t key_uuid;   /*!< the universal unique id based key identifier */
	uint32_t key_alg_id; /*!< an identifier for the algorithm used to encrypt the block device key */
	uint32_t key_size;   /*!< the length of the encrypted blob of secure block device key blob */
	uint8_t *key;        /*!< a pointer to the actual encrypted blob containing the key for the secure block device */
} sbdi_ks_t;

/*!
 * TODO Description
 */
typedef struct secure_block_device_interface_header {
	uint32_t version;
	sbdi_ks_t key_slots[8];
} sbdi_t;

int open(void);
ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);
void close(int filedes);

#endif /* SECBLOCK_H_ */

#ifdef __cplusplus
}
#endif
