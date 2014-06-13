/*
 * sbdi_siv.h
 *
 *  Created on: Jun 13, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif


#ifndef SBDI_SIV_H_
#define SBDI_SIV_H_

#include "siv.h"

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
void sbdi_siv_decrypt(siv_ctx *ctx, const unsigned char *c, unsigned char *p,
    const int len, unsigned char *counter, const int nad, ...);

/*!
 *
 * \brief This is a slightly modified aes cmac implementation to simplify block
 * index handling
 *
 * @param ctx[in] the siv context providing the key for the MAC operation
 * @param ad[in] the additional data
 * @param ad_len[in] the length of the additional data (must be
 * AES_BLOCK_SIZE)
 * @param msg[in] the message to compute the CMAC of
 * @param mlen[in] the length of the message
 * @param C[out] the resulting CMAC
 */
void sbdi_bl_aes_cmac(siv_ctx *ctx, const unsigned char *ad,
    const int ad_len, const unsigned char *msg, int mlen,
    unsigned char *C);

#endif /* SBDI_SIV_H_ */

#ifdef __cplusplus
}
#endif
