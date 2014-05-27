/*
 * Copyright (c) The Industrial Lounge, 2007
 *
 *  Copyright holder grants permission for redistribution and use in source
 *  and binary forms, with or without modification, provided that the
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *     3. All advertising materials and documentation mentioning features
 *	  or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Dan Harkins (dharkins at lounge dot org)"
 *
 *  "DISCLAIMER OF LIABILITY
 *
 *  THIS SOFTWARE IS PROVIDED BY THE INDUSTRIAL LOUNGE ``AS IS''
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under another distribution
 * license (including the GNU public license).
 */
#ifndef _SIV_H_
#define _SIV_H_

#include "aes.h"

#define AES_128_BYTES	16
#define AES_192_BYTES	24
#define AES_256_BYTES	32
#define SIV_256         256
#define SIV_384         384
#define SIV_512         512

typedef struct _siv_ctx {
  unsigned char K1[AES_BLOCK_SIZE];
  unsigned char K2[AES_BLOCK_SIZE];
  unsigned char T[AES_BLOCK_SIZE];
  unsigned char benchmark[AES_BLOCK_SIZE];
  AES_KEY ctr_sched;
  AES_KEY s2v_sched;
} siv_ctx;

#ifdef AES_LONG
typedef unsigned long u32;
#else
typedef unsigned int u32;
#endif
typedef unsigned short u16;
typedef unsigned char u8;

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((u32 *)(p)))
# define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
#else
# define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] << 8) ^ ((u32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >> 8); (ct)[3] = (u8)(st); }
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * exported APIs
 */
void aes_cmac(siv_ctx *, const unsigned char *, int, unsigned char *);
int siv_init(siv_ctx *, const unsigned char *, int);
void s2v_reset(siv_ctx *);
void s2v_benchmark(siv_ctx *);
void s2v_add(siv_ctx *, const unsigned char *);
void s2v_update(siv_ctx *, const unsigned char *, int);
int s2v_final(siv_ctx *, const unsigned char *, int, unsigned char *);
void vprf(siv_ctx *, unsigned char *, const int, ...);
void siv_restart(siv_ctx *);
void siv_aes_ctr(siv_ctx *, const unsigned char *, const int, unsigned char *,
    const unsigned char *);
int siv_encrypt(siv_ctx *, const unsigned char *, unsigned char *, const int,
    unsigned char *, const int, ...);
int siv_decrypt(siv_ctx *, const unsigned char *, unsigned char *, const int,
    unsigned char *, const int, ...);
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
#ifdef __cplusplus
}
#endif

#endif /* _SIV_H_ */
