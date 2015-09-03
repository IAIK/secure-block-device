/* Copyright (c) IAIK, Graz University of Technology, 2015.
 * All rights reserved.
 * Contact: http://opensource.iaik.tugraz.at
 * 
 * This file is part of the Secure Block Device Library.
 * 
 * Commercial License Usage
 * Licensees holding valid commercial licenses may use this file in
 * accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and SIC. For further information
 * contact us at http://opensource.iaik.tugraz.at.
 * 
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License as published by the Free Software Foundation version 2.
 * 
 * The Secure Block Device Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with the Secure Block Device Library. If not, see <http://www.gnu.org/licenses/>.
 */
///
/// \file
/// \brief Secure Block Device Library block layer interface.
///
/// The block layer handles all data operations on block granularity. Together
/// with the cache it implements the "plumbing" of the SBD: reading/writing and
/// protecting/checking data blocks.
///

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

sbdi_error_t sbdi_bl_verify_block_layer(sbdi_t *sbdi, mt_hash_t root);

sbdi_error_t sbdi_bl_verify_header(sbdi_t *sbdi, sbdi_block_t *hdr);

sbdi_error_t sbdi_bl_write_hdr_block(sbdi_t *sbdi, sbdi_block_t *hdr);

#endif /* SBDI_BLOCK_H_ */

#ifdef __cplusplus
}
#endif
