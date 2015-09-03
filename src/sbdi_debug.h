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
/// \brief Specifies functions used to debug the Secure Block Device Library.
///
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_DEBUG_H_
#define SBDI_DEBUG_H_

#include "sbdi_cache.h"

extern int debug;

#define SBDI_DBG(f) do {if (debug) {(f);}} while (0)

void sbdi_dbg_print_delim();
void sbdi_dbg_print_block(sbdi_block_t *blk);
void sbdi_dbg_print_cache_idx(sbdi_bc_t *cache);
void sbdi_dbg_print_sbdi_bl_write_data_block_params(unsigned char *ptr,
    uint32_t idx, size_t off, size_t len);

#endif /* SBDI_DEBUG_H_ */

#ifdef __cplusplus
}
#endif
