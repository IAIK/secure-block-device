/*
 * sbdi_debug.h
 *
 *  Created on: Jun 19, 2014
 *      Author: dhein
 */

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

#endif /* SBDI_DEBUG_H_ */

#ifdef __cplusplus
}
#endif
