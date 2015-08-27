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
 *    or use of this software must display the following acknowledgement:
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
#include "siv.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

/*
 * this is an implementation of SIV and S2V as defined in
 * "Deterministic Authenticated Encryption, A Provable-Security
 * Treatment of the Key-Wrap Problem" by Phil Rogaway and Tom
 * Shrimpton.
 *
 * http://www.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf
 */

#define Rb    0x87

const static unsigned char zero[AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*
 * xor()
 *  output ^= input
 */
static void xor(unsigned char *output, const unsigned char *input)
{
  int i;

  i = AES_BLOCK_SIZE - 1;
  do {
    output[i] ^= input[i];
    i--;
  } while (i >= 0);
  return;
}

/*
 * times_two()
 *  compute the product of 2 and "input" as a polynomial multiplication
 *  modulo the prime polynomial x^128 + x^7 + x^2 + x + 1
 */
static void times_two(unsigned char *output, unsigned char *input)
{
  int i;
  unsigned char *out = output, *in = input;
  unsigned char carry = 0;

  out = output + AES_BLOCK_SIZE - 1;
  in = input + AES_BLOCK_SIZE - 1;
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    *(out--) = (*in << 1) | carry;
    carry = (*(in--) & 0x80) ? 1 : 0;
  }

  if (carry) {
    output[AES_BLOCK_SIZE - 1] ^= Rb;
  }
  return;
}

/*
 * pad()
 *  add 10^* onto a buffer to pad it out to AES_BLOCK_SIZE len
 */
static void pad(unsigned char *buf, int len)
{
  int i;

  i = len;
  buf[i++] = 0x80;
  if (i < AES_BLOCK_SIZE) {
    memset(buf + i, 0, AES_BLOCK_SIZE - i);
  }
}

static inline void do_aes_cmac_work(siv_ctx *ctx, const unsigned char *msg, int mlen,
    unsigned char *C) {
  int n, i, slop;
  unsigned char Mn[AES_BLOCK_SIZE], *ptr;

  /*
     * n is the number of block-length blocks
     */
    n = (mlen + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE;

    /*
     * CBC mode for first n-1 blocks
     */
    ptr = (unsigned char *) msg;
    for (i = 0; i < (n - 1); i++) {
      xor(C, ptr);
      AES_encrypt(C, C, &ctx->s2v_sched);
      ptr += AES_BLOCK_SIZE;
    }

    /*
     * if last block is whole then (M ^ K1)
     * else (M || 10* ^ K2)
     */
    memset(Mn, 0, AES_BLOCK_SIZE);
    if ((slop = (mlen % AES_BLOCK_SIZE)) != 0) {
      memcpy(Mn, ptr, slop);
      pad(Mn, slop);
      xor(Mn, ctx->K2);
    } else {
      if (msg != NULL && mlen != 0) {
        memcpy(Mn, ptr, AES_BLOCK_SIZE);
        xor(Mn, ctx->K1);
      } else {
        pad(Mn, 0);
        xor(Mn, ctx->K2);
      }
    }
    /*
     * and do CBC with that xor'd and possibly padded block
     */
    xor(C, Mn);
    AES_encrypt(C, C, &ctx->s2v_sched);
    return;
}

/*
 * aes_cmac()
 *  CMAC mode of AES per NIST SP 800-38B
 */
void aes_cmac(siv_ctx *ctx, const unsigned char *msg, int mlen,
    unsigned char *C)
{
  int n, i, slop;
  unsigned char Mn[AES_BLOCK_SIZE], *ptr;

  memcpy(C, zero, AES_BLOCK_SIZE);

  /*
   * n is the number of block-length blocks
   */
  n = (mlen + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE;

  /*
   * CBC mode for first n-1 blocks
   */
  ptr = (unsigned char *) msg;
  for (i = 0; i < (n - 1); i++) {
    xor(C, ptr);
    AES_encrypt(C, C, &ctx->s2v_sched);
    ptr += AES_BLOCK_SIZE;
  }

  /*
   * if last block is whole then (M ^ K1)
   * else (M || 10* ^ K2)
   */
  memset(Mn, 0, AES_BLOCK_SIZE);
  if ((slop = (mlen % AES_BLOCK_SIZE)) != 0) {
    memcpy(Mn, ptr, slop);
    pad(Mn, slop);
    xor(Mn, ctx->K2);
  } else {
    if (msg != NULL && mlen != 0) {
      memcpy(Mn, ptr, AES_BLOCK_SIZE);
      xor(Mn, ctx->K1);
    } else {
      pad(Mn, 0);
      xor(Mn, ctx->K2);
    }
  }
  /*
   * and do CBC with that xor'd and possibly padded block
   */
  xor(C, Mn);
  AES_encrypt(C, C, &ctx->s2v_sched);
  return;
}

void sbdi_bl_aes_cmac(siv_ctx *ctx, const unsigned char *ad,
    const int ad_len, const unsigned char *msg, const int mlen,
    unsigned char *C) {
  assert(ad_len == AES_BLOCK_SIZE);

  memcpy(C, ad, AES_BLOCK_SIZE);
  AES_encrypt(C, C, &ctx->s2v_sched);

  do_aes_cmac_work(ctx, msg, mlen, C);
}

/*
 * s2v_final()
 *  input the last chunk into the s2v, output the digest
 */
int s2v_final(siv_ctx *ctx, const unsigned char *X, int xlen,
    unsigned char *digest)
{
  unsigned char T[AES_BLOCK_SIZE], C[AES_BLOCK_SIZE];
  unsigned char padX[AES_BLOCK_SIZE], *ptr;
  int blocks, i, slop;

  if (xlen < AES_BLOCK_SIZE) {
    /*
     * if it's less than the block size of the sPRF then
     * do another x2 of our running total and pad the
     * input before the final xor and sPRF.
     */
    memcpy(padX, X, xlen);
    pad(padX, xlen);

    times_two(T, ctx->T);
    xor(T, padX);
    aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
  } else {
    if (xlen == AES_BLOCK_SIZE) {
      /*
       * the final buffer is exactly the block size
       */
      memcpy(T, X, AES_BLOCK_SIZE);
      xor(T, ctx->T);
      aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
    } else {
      /*
       * -1 because the last 2 blocks get special treatment
       * and there's another -1 in the for loop below where
       * we AES-CMAC the buffer.
       */
      blocks = (xlen + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE - 1;
      ptr = (unsigned char *) X;
      memcpy(C, zero, AES_BLOCK_SIZE);
      if (blocks > 1) {
        /*
         * do AES-CMAC on all the buffers up to the last 2 blocks
         */
        for (i = 0; i < (blocks - 1); i++) {
          xor(C, ptr);
          AES_encrypt(C, C, &ctx->s2v_sched);
          ptr += AES_BLOCK_SIZE;
        }
      }
      memcpy(T, ptr, AES_BLOCK_SIZE);
      slop = xlen % AES_BLOCK_SIZE;
      if (slop) {
        /*
         * if there's slop then do the xor-end onto this block
         */
        for (i = 0; i < AES_BLOCK_SIZE - slop; i++) {
          T[i + slop] ^= ctx->T[i];
        }
        /*
         * continue with AES-CMAC on this partially xor'd buffer
         */
        xor(C, T);
        AES_encrypt(C, C, &ctx->s2v_sched);
        ptr += AES_BLOCK_SIZE;
        /*
         * now the final block is small so xor the end then pad and xor
         */
        memset(T, 0, AES_BLOCK_SIZE);
        memcpy(T, ptr, slop);
        for (i = 0; i < slop; i++) {
          T[i] ^= ctx->T[(AES_BLOCK_SIZE - slop) + i];
        }
        pad(T, slop);
        xor(T, ctx->K2);
      } else {
        /*
         * otherwise there's no slop so just AES-CMAC the next whole block
         */
        xor(C, ptr);
        AES_encrypt(C, C, &ctx->s2v_sched);
        ptr += AES_BLOCK_SIZE;
        /*
         * xor-end the entire last block...
         */
        memcpy(T, ptr, AES_BLOCK_SIZE);
        xor(T, ctx->T);
        /*
         * and treat it as the last (whole) block in AES-CMAC
         */
        xor(T, ctx->K1);
      }
      /*
       * a final CBC finishes AES-CMAC
       */
      xor(C, T);
      AES_encrypt(C, digest, &ctx->s2v_sched);
    }

  }
  return 0;
}

/*
 * s2v_add()
 *  add an sPRF'd string to s2v
 */
void s2v_add(siv_ctx *ctx, const unsigned char *Y)
{
  unsigned char T[AES_BLOCK_SIZE];

  memcpy(T, ctx->T, AES_BLOCK_SIZE);
  times_two(ctx->T, T);
  xor(ctx->T, Y);
}

/*
 * s2v_update()
 *  add a raw string to the s2v
 */
void s2v_update(siv_ctx *ctx, const unsigned char *X, int xlen)
{
  unsigned char Y[AES_BLOCK_SIZE];

  aes_cmac(ctx, X, xlen, Y);
  s2v_add(ctx, Y);
}

/*
 * siv_init()
 *  initiate an siv context
 */
int siv_init(siv_ctx *ctx, const unsigned char *key, int keylen)
{
  unsigned char L[AES_BLOCK_SIZE];

  memset((char *) ctx, 0, sizeof(siv_ctx));
  switch (keylen) {
  case SIV_512: /* a pair of 256 bit keys */
    AES_set_encrypt_key(key, 256, &ctx->s2v_sched);
    AES_set_encrypt_key(key + AES_256_BYTES, 256, &ctx->ctr_sched);
    break;
  case SIV_384: /* a pair of 192 bit keys */
    AES_set_encrypt_key(key, 192, &ctx->s2v_sched);
    AES_set_encrypt_key(key + AES_192_BYTES, 192, &ctx->ctr_sched);
    break;
  case SIV_256: /* a pair of 128 bit keys */
    AES_set_encrypt_key(key, 128, &ctx->s2v_sched);
    AES_set_encrypt_key(key + AES_128_BYTES, 128, &ctx->ctr_sched);
    break;
  default:
    return -1;
  }

  /*
   * compute CMAC subkeys
   */
  AES_encrypt(zero, L, &ctx->s2v_sched);
  times_two(ctx->K1, L);
  times_two(ctx->K2, ctx->K1);

  memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
  aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
  return 1;
}

/*
 * siv_restart()
 *  restart a siv context, same as siv_init but leaves the
 *  keying material alone
 */
void siv_restart(siv_ctx *ctx)
{
  memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
  memset(ctx->T, 0, AES_BLOCK_SIZE);
  aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
}

/*
 * s2v_benchmark()
 *  save intermediate T state for optimization
 */
void s2v_benchmark(siv_ctx *ctx)
{
  memcpy(ctx->benchmark, ctx->T, AES_BLOCK_SIZE);
}

/*
 * s2v_reset()
 *  copy the benchmarked state back to T
 */
void s2v_reset(siv_ctx *ctx)
{
  memcpy(ctx->T, ctx->benchmark, AES_BLOCK_SIZE);
}

/*
 * vPRF()
 */
void vprf(siv_ctx *ctx, unsigned char *outp, const int nad, ...)
{
  va_list ap;
  unsigned char *ad;
  int adlen, numad = nad;

  if (numad) {
    siv_restart(ctx);
    va_start(ap, nad);
    while (numad > 1) {
      ad = (unsigned char *) va_arg(ap, char *);
      adlen = va_arg(ap, int);
      s2v_update(ctx, ad, adlen);
      numad--;
    }
    ad = (unsigned char *) va_arg(ap, char *);
    adlen = va_arg(ap, int);
    s2v_final(ctx, ad, adlen, outp);
  }
}

/*
 * siv_aes_ctr()
 *      aes in CTR mode for SIV
 */
void siv_aes_ctr(siv_ctx *ctx, const unsigned char *p, const int lenp,
    unsigned char *c, const unsigned char *iv)
{
  int i, j;
  unsigned char ctr[AES_BLOCK_SIZE], ecr[AES_BLOCK_SIZE];
  unsigned long inc;

  memcpy(ctr, iv, AES_BLOCK_SIZE);
  /*
   * zero out the high order bits of the last two 32-bit words.
   * This allows ctr mode to be implemented mod sizeof(ulong)
   * or sizeof(longlong).
   *
   * we're just doing addition modulo 2^32 though....
   */
  ctr[12] &= 0x7f;
  ctr[8] &= 0x7f;
  inc = GETU32(ctr + 12);
  for (i = 0; i < lenp; i += AES_BLOCK_SIZE) {
    AES_encrypt(ctr, ecr, &ctx->ctr_sched);
    for (j = 0; j < AES_BLOCK_SIZE; j++) {
      if ((i + j) == lenp) {
        return;
      }
      c[i + j] = p[i + j] ^ ecr[j];
    }
    inc++;
    inc &= 0xffffffff;
    PUTU32(ctr + 12, inc);
  }
}

/*
 * siv_encrypt()
 *      perform S2V and CTR on plaintext. Output is c, the
 *      ciphertext, and counter, the CTR. One passes "nad"
 *      associated data pairs, each pair being an unsigned
 *      char pointing to a buffer of data and an integer length
 *      representing the length in bytes of that data.
 */
int siv_encrypt(siv_ctx *ctx, const unsigned char *p, unsigned char *c,
    const int len, unsigned char *counter, const int nad, ...)
{
  va_list ap;
  unsigned char *ad;
  int adlen, numad = nad;
  unsigned char ctr[AES_BLOCK_SIZE];

  if (numad) {
    va_start(ap, nad);
    while (numad) {
      ad = (unsigned char *) va_arg(ap, char *);
      adlen = va_arg(ap, int);
      s2v_update(ctx, ad, adlen);
      numad--;
    }
  }
  s2v_final(ctx, p, len, ctr);
  memcpy(counter, ctr, AES_BLOCK_SIZE);
  siv_aes_ctr(ctx, p, len, c, ctr);
  /*
   * the only part of the context that is carried along with
   * subsequent calls to siv_encrypt() are the keys, so reset
   * everything else.
   */
  siv_restart(ctx);
  return 1;
}

/*
 * siv_decrypt()
 *      do CTR to decrypt an SIV-encrypted ciphertext and then
 *      verify the given counter is the output of S2V. One passes
 *      "nad" associated data pairs, each pair being an unsigned
 *      char pointing to a buffer of data and an integer length
 *      representing the length in bytes of that data.
 */
int siv_decrypt(siv_ctx *ctx, const unsigned char *c, unsigned char *p,
    const int len, unsigned char *counter, const int nad, ...)
{
  va_list ap;
  unsigned char *ad;
  int adlen, numad = nad;
  unsigned char ctr[AES_BLOCK_SIZE];

  memcpy(ctr, counter, AES_BLOCK_SIZE);
  siv_aes_ctr(ctx, c, len, p, ctr);
  if (numad) {
    va_start(ap, nad);
    while (numad) {
      ad = (unsigned char *) va_arg(ap, char *);
      adlen = va_arg(ap, int);
      s2v_update(ctx, ad, adlen);
      numad--;
    }
  }
  s2v_final(ctx, p, len, ctr);

  /*
   * the only part of the context that is carried along with
   * subsequent calls to siv_decrypt() are the keys, so reset
   * everything else.
   */
  siv_restart(ctx);
  if (memcmp(ctr, counter, AES_BLOCK_SIZE)) {
    memset(p, 0, len);
    return -1; /* FAIL */
  } else {
    return 1;
  }
}
