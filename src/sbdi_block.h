/*
 * sbdi_block.h
 *
 *  Created on: May 18, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_BLOCK_H_
#define SBDI_BLOCK_H_

#include "merkletree.h"

#include "sbdi_config.h"
#include "sbdi_blic.h"
#include "sbdi_cache.h"
#include "sbdi_ctr_128b.h"

sbdi_error_t sbdi_bl_sync(void *sbdi, sbdi_block_t *blk);

sbdi_error_t sbdi_bl_read_block(const sbdi_t *sbdi, sbdi_block_t *blk,
    size_t len, uint32_t *read);

sbdi_error_t sbdi_bl_read_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t off, size_t len);

sbdi_error_t sbdi_bl_write_data_block(sbdi_t *sbdi, unsigned char *ptr,
    uint32_t idx, size_t off, size_t len);

sbdi_error_t sbdi_bl_verify_block_layer(sbdi_t *sbdi, mt_hash_t root,
    uint32_t last_blk_idx);

sbdi_error_t sbdi_bl_verify_header(sbdi_t *sbdi, sbdi_block_t *hdr);

sbdi_error_t sbdi_bl_write_hdr_block(sbdi_t *sbdi, sbdi_block_t *hdr);

#endif /* SBDI_BLOCK_H_ */

#ifdef __cplusplus
}
#endif
