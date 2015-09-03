///
/// \file
/// \brief Specifies a Secure Block Device Library cryptographic abstraction
/// layer that uses AES-CBC and HMAC-SHA256.
///
/// This cryptographic abstraction layer is implemented for comparison only.
///
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_HMAC_H_
#define SBDI_HMAC_H_

#include "sbdi_crypto.h"

sbdi_error_t sbdi_hmac_create(sbdi_crypto_t **crypto, const sbdi_key_t key);
void sbdi_hmac_destroy(sbdi_crypto_t *crypto);

#endif /* SBDI_HMAC_H_ */

#ifdef __cplusplus
}
#endif
