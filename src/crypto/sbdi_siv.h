///
/// \file
/// \brief Specifies a Secure Block Device Library cryptographic abstraction
/// layer using the AES SIV mode of operation for data block protection and
/// AES CMAC for management block protection.
///
#ifdef __cplusplus
extern "C" {
#endif


#ifndef SBDI_SIV_H_
#define SBDI_SIV_H_

#include "siv.h"

#include "sbdi_crypto.h"

/*!
 * \brief A version of siv_decrypt that omits the tag check. DEPRECATED!
 *
 * This function is required for the merkle hash tree based integrity
 * protection mechanism used by the secure block device interface.
 *
 * @param ctx[in] the siv context
 * @param c[in] the ciphertext
 * @param p[out] the plaintext
 * @param len[in] the length of the plaintext (also the length of the
 * ciphertext)
 * @param counter[out] the block tag
 * @param nad[in] the number of (unsigned char *, int) length tuples describing
 * additional header information for the mac.
 */
void sbdi_siv_decrypt_dep(siv_ctx *ctx, const unsigned char *c, unsigned char *p,
    const int len, unsigned char *counter, const int nad, ...);

sbdi_error_t sbdi_siv_create(sbdi_crypto_t **crypto, const sbdi_key_t key);
void sbdi_siv_destroy(sbdi_crypto_t *crypto);

#endif /* SBDI_SIV_H_ */

#ifdef __cplusplus
}
#endif
