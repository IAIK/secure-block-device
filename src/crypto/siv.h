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

/*
 * exported APIs
 */
void aes_cmac (siv_ctx *, const unsigned char *, int, unsigned char *);
int siv_init(siv_ctx *, const unsigned char *, int);
void siv_reset(siv_ctx *);
void s2v_benchmark(siv_ctx *);
void s2v_add(siv_ctx *, const unsigned char *);
void s2v_update(siv_ctx *, const unsigned char *, int);
int s2v_final(siv_ctx *, const unsigned char *, int, unsigned char *);
void siv_restart(siv_ctx *);
void siv_aes_ctr(siv_ctx *, const unsigned char *, const int, unsigned char *,
                 const unsigned char *);
int siv_encrypt (siv_ctx *ctx, const unsigned char *p, unsigned char *c,
             const int len, unsigned char *counter,
             const int nad, const int* adlens, const unsigned char** ads);
int siv_decrypt(siv_ctx *, const unsigned char *, unsigned char *,
                const int, unsigned char *,
                const int nad, const int* adlens, const unsigned char** ads);

#endif /* _SIV_H_ */
