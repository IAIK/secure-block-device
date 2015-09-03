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
/// \brief Specifies the interface of a 128-bit counter.
///
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_CTR_128B_H_
#define SBDI_CTR_128B_H_

#include "sbdi_err.h"
#include <stdint.h>

#define SBDI_CTR_128B_SIZE 16

typedef struct sbdi_counter_128bit {
  uint64_t hi;
  uint64_t lo;
} sbdi_ctr_128b_t;

sbdi_error_t sbdi_ctr_128b_init(sbdi_ctr_128b_t *ctr, uint64_t hi, uint64_t lo);
sbdi_error_t sbdi_ctr_128b_reset(sbdi_ctr_128b_t *ctr);
sbdi_error_t sbdi_ctr_128b_inc(sbdi_ctr_128b_t *ctr);
sbdi_error_t sbdi_ctr_128b_dec(sbdi_ctr_128b_t *ctr);
sbdi_error_t sbdi_ctr_128b_cmp(const sbdi_ctr_128b_t *ctr1, const sbdi_ctr_128b_t *ctr2,
    int *res);
void sbdi_ctr_128b_print(sbdi_ctr_128b_t *ctr);

#endif /* SBDI_CTR_128B_H_ */

#ifdef __cplusplus
}
#endif
