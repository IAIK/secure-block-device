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

#include "sbdi_block.h"

#include <sys/types.h>
#include <stdint.h>

static const uint8_t sbdi_siv_master_key[32] = {
    0xa7, 0xde, 0x2e, 0xb8, 0xf7, 0xc2, 0x85, 0xa6,
    0x66, 0x27, 0x9c, 0xa4, 0x8e, 0x4c, 0xb5, 0xda,
    0x98, 0xaf, 0x8c, 0x50, 0x5d, 0xe6, 0x4a, 0xf0,
    0x29, 0x87, 0x6e, 0x34, 0x4c, 0x0b, 0x9b, 0x5a
};


sbdi_t *sbdi_open(void);
ssize_t sbdi_pread(sbdi_t *sbdi, void *buf, size_t nbyte, off_t offset);
ssize_t sbdi_pwrite(sbdi_t *sbdi, const void *buf, size_t nbyte, off_t offset);
void sbdi_close(sbdi_t *sbdi);

#endif /* SECURE_BLOCK_DEVICE_INTERFACE_H_ */

#ifdef __cplusplus
}
#endif
