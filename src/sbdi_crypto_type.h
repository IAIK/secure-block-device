/*
 * sbdi_crypto_type.h
 *
 *  Created on: Jun 19, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_CRYPTO_TYPE_H_
#define SBDI_CRYPTO_TYPE_H_

#include "sbdi_config.h"

/*!
 * \brief Used to select which cryptographic abstraction layer to use
 */
typedef enum sbdi_crypto_type {
  SBDI_CRYPTO_NONE = SBDI_CRYPTO_TYPE_NONE, /*!< Crypto operations implemented as no operations */                                               //!< SBDI_CRYPTO_NONE
  SBDI_CRYPTO_SIV = SBDI_CRYPTO_TYPE_SIV, /*!< Crypto operations implemented using the SIV authenticated encryption mode of operation with AES *///!< SBDI_CRYPTO_SIV
  SBDI_CRYPTO_OCB = SBDI_CRYPTO_TYPE_OCB /*!< Crypto operations implemented using the OCB authenticated encryption mode of operation with AES */ //!< SBDI_CRYPTO_OCB
} sbdi_crypto_type_t;

#endif /* SBDI_CRYPTO_TYPE_H_ */

#ifdef __cplusplus
}
#endif
