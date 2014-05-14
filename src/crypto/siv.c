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

#define Rb    0x87

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

static void pad(unsigned char *buf, int len)
{
  int i;

  i = len;
  buf[i++] = 0x80;
  if (i < AES_BLOCK_SIZE) {
    memset(buf + i, 0, AES_BLOCK_SIZE - i);
  }
}

void aes_cmac(siv_ctx *ctx, const unsigned char *msg, int mlen,
    unsigned char *C)
{
  int n, i, slop;
  unsigned char Mn[AES_BLOCK_SIZE], *ptr;

  // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
  // a global, as in the original program.
  unsigned char zero[AES_BLOCK_SIZE] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  memcpy(C, zero, AES_BLOCK_SIZE);

  n = (mlen + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE;

  ptr = (unsigned char *) msg;
  for (i = 0; i < (n - 1); i++) {
    xor(C, ptr);
    AES_encrypt(C, C, &ctx->s2v_sched);
    ptr += AES_BLOCK_SIZE;
  }

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
  xor(C, Mn);
  AES_encrypt(C, C, &ctx->s2v_sched);
  return;
}

int s2v_final(siv_ctx *ctx, const unsigned char *X, int xlen,
    unsigned char *digest)
{
  unsigned char T[AES_BLOCK_SIZE], C[AES_BLOCK_SIZE];
  unsigned char padX[AES_BLOCK_SIZE], *ptr;
  int blocks, i, slop;

  // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
  // a global, as in the original program.
  unsigned char zero[AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  if (xlen < AES_BLOCK_SIZE) {
    memcpy(padX, X, xlen);
    pad(padX, xlen);

    times_two(T, ctx->T);
    xor(T, padX);
    aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
  } else {
    if (xlen == AES_BLOCK_SIZE) {
      memcpy(T, X, AES_BLOCK_SIZE);
      xor(T, ctx->T);
      aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
    } else {
      blocks = (xlen + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE - 1;
      ptr = (unsigned char *) X;
      memcpy(C, zero, AES_BLOCK_SIZE);
      if (blocks > 1) {
        for (i = 0; i < (blocks - 1); i++) {
          xor(C, ptr);
          AES_encrypt(C, C, &ctx->s2v_sched);
          ptr += AES_BLOCK_SIZE;
        }
      }
      memcpy(T, ptr, AES_BLOCK_SIZE);
      slop = xlen % AES_BLOCK_SIZE;
      if (slop) {
        for (i = 0; i < AES_BLOCK_SIZE - slop; i++) {
          T[i + slop] ^= ctx->T[i];
        }
        xor(C, T);
        AES_encrypt(C, C, &ctx->s2v_sched);
        ptr += AES_BLOCK_SIZE;
        memset(T, 0, AES_BLOCK_SIZE);
        memcpy(T, ptr, slop);
        for (i = 0; i < slop; i++) {
          T[i] ^= ctx->T[(AES_BLOCK_SIZE - slop) + i];
        }
        pad(T, slop);
        xor(T, ctx->K2);
      } else {
        xor(C, ptr);
        AES_encrypt(C, C, &ctx->s2v_sched);
        ptr += AES_BLOCK_SIZE;
        memcpy(T, ptr, AES_BLOCK_SIZE);
        xor(T, ctx->T);
        xor(T, ctx->K1);
      }
      xor(C, T);
      AES_encrypt(C, digest, &ctx->s2v_sched);
    }

  }
  return 0;
}

void s2v_add(siv_ctx *ctx, const unsigned char *Y)
{
  unsigned char T[AES_BLOCK_SIZE];

  memcpy(T, ctx->T, AES_BLOCK_SIZE);
  times_two(ctx->T, T);
  xor(ctx->T, Y);
}

void s2v_update(siv_ctx *ctx, const unsigned char *X, int xlen)
{
  unsigned char Y[AES_BLOCK_SIZE];

  aes_cmac(ctx, X, xlen, Y);
  s2v_add(ctx, Y);
}

int siv_init(siv_ctx *ctx, const unsigned char *key, int keylen)
{
  unsigned char L[AES_BLOCK_SIZE];

  // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
  // a global, as in the original program.
  unsigned char zero[AES_BLOCK_SIZE] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  memset((char *) ctx, 0, sizeof(siv_ctx));
  switch (keylen) {
  case SIV_512:
    AES_set_encrypt_key(key, 256, &ctx->s2v_sched);
    AES_set_encrypt_key(key + AES_256_BYTES, 256, &ctx->ctr_sched);
    break;
  case SIV_384:
    AES_set_encrypt_key(key, 192, &ctx->s2v_sched);
    AES_set_encrypt_key(key + AES_192_BYTES, 192, &ctx->ctr_sched);
    break;
  case SIV_256:
    AES_set_encrypt_key(key, 128, &ctx->s2v_sched);
    AES_set_encrypt_key(key + AES_128_BYTES, 128, &ctx->ctr_sched);
    break;
  default:
    return -1;
  }

  AES_encrypt(zero, L, &ctx->s2v_sched);
  times_two(ctx->K1, L);
  times_two(ctx->K2, ctx->K1);

  memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
  aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
  return 1;
}

void siv_restart(siv_ctx *ctx)
{
  // NOTE(jacobsa): For some reason, weird things happen when when `zero` is
  // a global, as in the original program.
  unsigned char zero[AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
  memset(ctx->T, 0, AES_BLOCK_SIZE);
  aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
}

void s2v_benchmark(siv_ctx *ctx)
{
  memcpy(ctx->benchmark, ctx->T, AES_BLOCK_SIZE);
}

void s2v_reset(siv_ctx *ctx)
{
  memcpy(ctx->T, ctx->benchmark, AES_BLOCK_SIZE);
}

void siv_aes_ctr(siv_ctx *ctx, const unsigned char *p, const int lenp,
    unsigned char *c, const unsigned char *iv)
{
  int i, j;
  unsigned char ctr[AES_BLOCK_SIZE], ecr[AES_BLOCK_SIZE];
  unsigned long inc;

  memcpy(ctr, iv, AES_BLOCK_SIZE);
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

int siv_encrypt(siv_ctx *ctx, const unsigned char *p, unsigned char *c,
    const int len, unsigned char *counter, const int nad, const int* adlens,
    const unsigned char** ads)
{
  const unsigned char *ad;
  int adlen;
  int i;
  unsigned char ctr[AES_BLOCK_SIZE];

  for (i = 0; i < nad; ++i) {
    ad = ads[i];
    adlen = adlens[i];
    s2v_update(ctx, ad, adlen);
  }

  s2v_final(ctx, p, len, ctr);
  memcpy(counter, ctr, AES_BLOCK_SIZE);
  siv_aes_ctr(ctx, p, len, c, ctr);
  siv_restart(ctx);
  return 1;
}

int siv_decrypt(siv_ctx *ctx, const unsigned char *c, unsigned char *p,
    const int len, unsigned char *counter, const int nad, const int* adlens,
    const unsigned char** ads)
{
//  va_list ap;
  const unsigned char *ad;
  int adlen;
  int i;
  unsigned char ctr[AES_BLOCK_SIZE];

  memcpy(ctr, counter, AES_BLOCK_SIZE);
  siv_aes_ctr(ctx, c, len, p, ctr);
  for (i = 0; i < nad; ++i) {
    ad = ads[i];
    adlen = adlens[i];
    s2v_update(ctx, ad, adlen);
  }
  s2v_final(ctx, p, len, ctr);

  siv_restart(ctx);
  if (memcmp(ctr, counter, AES_BLOCK_SIZE)) {
    memset(p, 0, len);
    return -1;
  } else {
    return 1;
  }
}
