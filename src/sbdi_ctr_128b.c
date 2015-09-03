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
/// \brief Implements a 128-bit counter
///
#include "sbdi_ctr_128b.h"

#include <inttypes.h>
#include <stdio.h>

//----------------------------------------------------------------------
sbdi_error_t sbdi_ctr_128b_init(sbdi_ctr_128b_t *ctr, uint64_t hi, uint64_t lo)
{
  if (!ctr) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ctr->hi = hi;
  ctr->lo = lo;
  return SBDI_SUCCESS;
}
//----------------------------------------------------------------------
sbdi_error_t sbdi_ctr_128b_reset(sbdi_ctr_128b_t *ctr)
{
  if (!ctr) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  ctr->hi = 0;
  ctr->lo = 0;
  return SBDI_SUCCESS;
}
//----------------------------------------------------------------------
sbdi_error_t sbdi_ctr_128b_inc(sbdi_ctr_128b_t *ctr)
{
  if (!ctr) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (ctr->lo == UINT64_MAX) {
    if (ctr->hi == UINT64_MAX) {
      return SBDI_ERR_ILLEGAL_STATE;
    } else {
      ctr->lo = 0;
      ctr->hi += 1;
    }
  } else {
    ctr->lo += 1;
  }
  return SBDI_SUCCESS;
}
//----------------------------------------------------------------------
sbdi_error_t sbdi_ctr_128b_dec(sbdi_ctr_128b_t *ctr)
{
  if (!ctr) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (ctr->lo == 0) {
    if (ctr->hi == 0) {
      return SBDI_ERR_ILLEGAL_STATE;
    } else {
      ctr->lo = UINT64_MAX;
      ctr->hi -= 1;
    }
  } else {
    ctr->lo -= 1;
  }
  return SBDI_SUCCESS;
}
//----------------------------------------------------------------------
sbdi_error_t sbdi_ctr_128b_cmp(const sbdi_ctr_128b_t *ctr1,
    const sbdi_ctr_128b_t *ctr2, int *res)
{
  if (!ctr1 || !ctr2 || !res) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (ctr1->hi == ctr2->hi) {
    if (ctr1->lo == ctr2->lo) {
      // Identical
      *res = 0;
    } else {
      // Counter differing in low part
      if (ctr1->lo < ctr2->lo) {
        *res =  -1;
      } else {
        *res =  1;
      }
    }
  } else {
    // Counter differing in high part
    if (ctr1->hi < ctr2->hi) {
      *res =  -1;
    } else {
      *res =  1;
    }
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
void sbdi_ctr_128b_print(sbdi_ctr_128b_t *ctr)
{
  if (!ctr) {
    fprintf(stderr, "[ERROR][sbdi_ctr_128b_print]: Counter is NULL");
    return;
  }
  printf("0x%" PRIx64 "%" PRIx64 "\n", ctr->hi, ctr->lo);
}
//----------------------------------------------------------------------
