/*
 * sbdi_ctr_128b.h
 *
 *  Created on: May 15, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_CTR_128B_H_
#define SBDI_CTR_128B_H_

#include "sbdi_err.h"
#include <stdint.h>

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
