/*
 * sbdi.h
 *
 *  Created on: May 23, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_H_
#define SBDI_H_

#include "merkletree.h"

#include "sbdi_config.h"
#include "sbdi_block.h"
#include "sbdi_cache.h"
#include "sbdi_ctr_128b.h"

typedef struct secure_block_device_interface {
  int fd;
  void *ctx;
  void *mt;
  sbdi_bc_t *cache;
  sbdi_db_t write_store_dat[2];
  sbdi_block_t write_store[2];
  sbdi_ctr_128b_t g_ctr;
} sbdi_t;

sbdi_error_t sbdi_bl_sync(void *sbdi, sbdi_block_t *blk);

sbdi_t *sbdi_create(int fd, uint8_t *key, size_t key_len);
void sbdi_delete(sbdi_t *sbdi);

sbdi_error_t sbdi_bl_read_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t len);

sbdi_error_t sbdi_bl_write_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t len);

sbdi_error_t sbdi_bl_verify_block_layer(sbdi_t *sbdi, mt_hash_t root, uint32_t last_blk_idx);

sbdi_error_t sbdi_bl_get_mt_root(sbdi_t *sbdi);

#endif /* SBDI_H_ */

#ifdef __cplusplus
}
#endif
