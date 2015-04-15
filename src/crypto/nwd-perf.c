///
/// \file
/// \brief Normal World Crypto Performance Test
///
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>

#include "nwd-stopwatch.h"


// Pull-in the normal world APIs
#include "sbdi_nocrypto.h"
#include "sbdi_ocb.h"
#include "sbdi_siv.h"
#include "sbdi_hmac.h"
#include "sbdi_buffer.h"

static const sbdi_key_t key = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x10,
};

typedef void (*sbdi_crypto_destroy)(sbdi_crypto_t *crypto);

//----------------------------------------------------------------------
#define SBDI_BLOCK_SIZE         4096u //!< The block size of the secure block device interface
#define SBDI_BLOCK_CTR_SIZE       16u //!< The size in bytes of the counter (nonce) used to make every block write unique
#define SBDI_BLOCK_TAG_SIZE       16u //!< The size in bytes of a cryptographic block tag (a mac over a single block)

#define NWD_PERF_MAX_BLOCK_COUNT 256u //!< Maximum block count
#define NWD_PERF_RUNS_PER_OP       3u //!< Runs per operation
#define NWD_PERF_MAJOR_LOOPS      10u //!< Major loops for encrypt and decrypt

// Enable (define) to compare decryption results with plaintexts
#define NWD_PERF_CRYPTO_CHECKS 1

#if NWD_PERF_CRYPTO_CHECKS
static uint8_t g_block_ref[NWD_PERF_MAX_BLOCK_COUNT * SBDI_BLOCK_SIZE];
#endif

static uint8_t g_block_data[NWD_PERF_MAX_BLOCK_COUNT * SBDI_BLOCK_SIZE];
static uint8_t g_block_ciph[NWD_PERF_MAX_BLOCK_COUNT * SBDI_BLOCK_SIZE];
static uint8_t g_block_tags[NWD_PERF_MAX_BLOCK_COUNT * SBDI_BLOCK_TAG_SIZE];

#define SBDI_ERR_CHECK(ret)                                     \
  do {                                                          \
    sbdi_error_t _ret = (ret);                                  \
    if (_ret != SBDI_SUCCESS) {                                 \
      fprintf(stderr, "fatal sbdi error %s(%d): [%d] %s\n",     \
              __FILE__, __LINE__, (int) (_ret), #ret);          \
      abort();                                                  \
    }                                                           \
  } while(0)

//----------------------------------------------------------------------
typedef struct sbdi_perf_setup {
  sbdi_crypto_t *crypto;
  uint8_t *plaintext;
  uint8_t *ciphertext;
  uint8_t *tag;
  size_t idx;
  sbdi_ctr_128b_t *ctr;
} sbdi_perf_setup_t;

static void nwd_perf_encrypt(void *arg);
static void nwd_perf_decrypt(void *arg);
static void nwd_perf_random(uint8_t *data, size_t size);
static void nwd_perf_test(const char *name, size_t num_blocks,
                          sbdi_error_t (*create)(sbdi_crypto_t **crypto, const sbdi_key_t key),
                          void (*destroy)(sbdi_crypto_t *crypto));

//----------------------------------------------------------------------
int main(void)
{
  nwd_stopwatch_init();

  // Setup random data (and create a reference copy)
  nwd_perf_random(g_block_data, sizeof(g_block_data));

  // No crypto
  //
  // FIXME: Check why we need the "spurious" MAC here??
  nwd_perf_test("nocrypto", NWD_PERF_MAX_BLOCK_COUNT,
                &sbdi_nocrypto_create, &sbdi_nocrypto_destroy);

  // OCB mode
  nwd_perf_test("ocb", NWD_PERF_MAX_BLOCK_COUNT,
                &sbdi_ocb_create, &sbdi_ocb_destroy);

  // SIV mode
  nwd_perf_test("siv", NWD_PERF_MAX_BLOCK_COUNT,
                &sbdi_siv_create, &sbdi_siv_destroy);

  // HMAC mode
  nwd_perf_test("hmac", NWD_PERF_MAX_BLOCK_COUNT,
                &sbdi_hmac_create, &sbdi_hmac_destroy);
  return 0;
}

//----------------------------------------------------------------------
static void nwd_perf_random(uint8_t *data, size_t size)
{
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd == -1) {
    perror("failed to open /dev/urandom");
    abort();
  }

  if (read(fd, data, size) != size) {
    perror("failed to read random bytes from /dev/urandom");
    abort();
  }

  close(fd);
}

//----------------------------------------------------------------------
static void nwd_perf_test(const char *name, size_t num_blocks,
                          sbdi_error_t (*create)(sbdi_crypto_t **crypto, const sbdi_key_t key),
                          void (*destroy)(sbdi_crypto_t *crypto))
{
  sbdi_crypto_t *ctx = NULL;
  sbdi_ctr_128b_t ctr;

  printf("perf %s start\n", name);

  SBDI_ERR_CHECK(create(&ctx, key));

  // Prepare test blocks
  memset(g_block_data, 0, sizeof(g_block_data));
  nwd_perf_random(g_block_data, num_blocks * NWD_PERF_MAX_BLOCK_COUNT);

#if NWD_PERF_CRYPTO_CHECKS
  // Sample reference blocks
  memcpy(g_block_ref, g_block_data, sizeof(g_block_data));
#endif

  // We assume all block counters as zero (for simplicity)
  SBDI_ERR_CHECK(sbdi_ctr_128b_init(&ctr, 0, 0));

  // Run the encryption tests (this will create valid ciphertexts and tags)
  for (size_t k = 0; k < NWD_PERF_MAJOR_LOOPS; ++k) {
    printf("perf %s encrypt(%u) ", name, (unsigned) k);
    for (size_t i = 0; i < num_blocks; ++i) {
      uint8_t *plaintext  = g_block_data + i * SBDI_BLOCK_SIZE;
      uint8_t *ciphertext = g_block_ciph + i * SBDI_BLOCK_SIZE;
      uint8_t *tag        = g_block_tags + i * SBDI_BLOCK_TAG_SIZE;

      // Clear ciphertext and tag
      memset(ciphertext, 0, SBDI_BLOCK_SIZE);
      memset(tag, 0, SBDI_BLOCK_TAG_SIZE);

      // Run the actual encryption
      sbdi_perf_setup_t op_ctx = {
        .crypto = ctx,
        .plaintext = plaintext,
        .ciphertext = ciphertext,
        .tag = tag,
        .ctr = &ctr,
        .idx = i,
      };

      int64_t duration = nwd_stopwatch_measure(&nwd_perf_encrypt, &op_ctx, NWD_PERF_RUNS_PER_OP);
      printf(" %" PRId64, duration);
      fflush(stdout);
    }
    printf("\n");
  }

  // Run the decryption tests (we have valid tags and ciphertexts from above)
  for (size_t k = 0; k < NWD_PERF_MAJOR_LOOPS; ++k) {
    printf("perf %s decrypt(%u)", name, (unsigned) k);
    for (size_t i = 0; i < num_blocks; ++i) {
      uint8_t *plaintext  = g_block_data + i * SBDI_BLOCK_SIZE;
      uint8_t *ciphertext = g_block_ciph + i * SBDI_BLOCK_SIZE;
      uint8_t *tag        = g_block_tags + i * SBDI_BLOCK_TAG_SIZE;

      // Clear ciphertext and tag
      memset(plaintext, 0, SBDI_BLOCK_SIZE);

      // Run the actual encryption
      sbdi_perf_setup_t op_ctx = {
        .crypto = ctx,
        .plaintext = plaintext,
        .ciphertext = ciphertext,
        .tag = tag,
        .ctr = &ctr,
        .idx = i,
      };

      int64_t duration = nwd_stopwatch_measure(&nwd_perf_decrypt, &op_ctx, NWD_PERF_RUNS_PER_OP);
      printf(" %" PRId64, duration);
      fflush(stdout);

#if NWD_PERF_CRYPTO_CHECKS
      // Sanity check: Must be at reference value again
      const uint8_t *ref_plaintext = g_block_ref + i * SBDI_BLOCK_SIZE;
      if (memcmp(plaintext, ref_plaintext, SBDI_BLOCK_SIZE) != 0) {
        fprintf(stderr, "corrupted data after decryption\n");
        abort();
      }
#endif
    }
    printf("\n");
  }

  destroy(ctx);

  printf("perf %s --stop--\n", name);
  fflush(stdout);
}

//----------------------------------------------------------------------
static void nwd_perf_encrypt(void *arg)
{
  sbdi_perf_setup_t *ctx = arg;

  // First encrypt
  SBDI_ERR_CHECK((ctx->crypto->enc)(ctx->crypto->ctx, ctx->plaintext, SBDI_BLOCK_SIZE,
                                    ctx->ctr, ctx->idx, ctx->ciphertext, ctx->tag));
}

//----------------------------------------------------------------------
static void nwd_perf_decrypt(void *arg)
{
  sbdi_perf_setup_t *ctx = arg;
  SBDI_ERR_CHECK((ctx->crypto->dec)(ctx->crypto->ctx, ctx->ciphertext, SBDI_BLOCK_SIZE,
                                    (uint8_t *) ctx->ctr, ctx->idx,
                                    ctx->plaintext, ctx->tag));
}
//----------------------------------------------------------------------
// Pull in relevant parts of the SBDI implementation
//
#include "sbdi_ctr_128b.c"
#include "sbdi_buffer.c"
