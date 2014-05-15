/*
 * sbdi_ctr_128b.c
 *
 *  Created on: May 15, 2014
 *      Author: dhein
 */

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
sbdi_error_t sbdi_ctr_128b_cmp(const sbdi_ctr_128b_t *ctr1, const sbdi_ctr_128b_t *ctr2,
    int *res)
{
  if (!ctr1 || !ctr2) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  uint64_t hi = ctr1->hi - ctr2->hi;
  if (hi != 0) {
    *res = (hi < ctr1->hi) ? 1 : -1;
  } else {
    uint64_t lo = ctr1->lo - ctr2->lo;
    if (lo != 0) {
      *res = (lo < ctr1->lo) ? 1 : -1;
    } else {
      *res = 0;
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
