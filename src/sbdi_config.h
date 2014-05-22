/*
 * sbdi_config.h
 *
 *  Created on: May 16, 2014
 *      Author: dhein
 */

#ifndef SBDI_CONFIG_H_
#define SBDI_CONFIG_H_

#include "config.h"
#include "sbdi_err.h"

#define SBDI_ERR_CHK(f) do {sbdi_error_t r = f;if (r != SBDI_SUCCESS) {return r;}} while (0)

#endif /* SBDI_CONFIG_H_ */
