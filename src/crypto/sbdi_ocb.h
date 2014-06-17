/*
 * sbdi_ocb.h
 *
 *  Created on: Jun 17, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_OCB_H_
#define SBDI_OCB_H_

#include "sbdi_crypto.h"

/*!
 * \brief Creates a new cryptographic abstraction layer for use with the
 * secure block device interface that uses AES in OCB mode and AES CMAC to
 * implement its cryptographic operations
 *
 * The created cryptographic abstraction layer uses the lower 16 bytes of the
 * key for the CMAC and the upper 16 bytes of the key for OCB.
 *
 * @param crypto[out] a pointer pointer that will be set to the newly created
 * cryptographic abstraction layer
 * @param key[in] the key to use for the cryptographic operations
 * @return SBDI_SUCCESS if the creation of the cryptographic abstraction
 *                      layer is successful;
 *         SBDI_OUT_OF_MEMORY if there was insufficient memory to create the
 *                            OCB context, the SIV (CMAC) context, the
 *                            wrapper context, or the cryptographic
 *                            abstraction layer itself
 *         SBDI_ERR_CRYPTO_FAIL if creation of the OCB AE, or the SIV context
 *                              fails
 */
sbdi_error_t sbdi_ocb_create(sbdi_crypto_t **crypto, const sbdi_key_t key);

/*!
 * \brief Cleans up the given cryptographic abstraction layer by freeing all
 * associated resources
 *
 * Warning: Only apply this function to cryptographic abstraction layers
 * created with the sbdi_ocb_create function!
 *
 * @param crypto[in] the cryptographic abstraction layer to destroy
 */
void sbdi_ocb_destroy(sbdi_crypto_t *crypto);

#endif /* SBDI_OCB_H_ */

#ifdef __cplusplus
}
#endif
