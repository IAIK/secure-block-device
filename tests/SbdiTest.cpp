///
/// \file
/// \brief Tests the Secure Block Device Library API.
///
/// If you are interested in an example on how to use the Secure Block Device
/// Library in your application this is a good place to start.
///
#ifndef UINT32_MAX
#include <limits>
#define UINT32_MAX std::numeric_limits<uint32_t>::max()
#endif
#ifndef UINT32_C
#define UINT32_C(c) c ## u
#endif
#ifndef UINT16_MAX
#define UINT16_MAX 65535u
#endif
#ifndef UINT8_MAX
#define UINT8_MAX 255u
#endif

#include "SbdiTest.h"
#include "SecureBlockDeviceInterface.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <cppunit/extensions/HelperMacros.h>

#include <algorithm>
#include <vector>
#include <cstdlib>

class SbdiTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE( SbdiTest );
  CPPUNIT_TEST(testParameterChecks);
  CPPUNIT_TEST(testSimpleReadWrite);
  CPPUNIT_TEST(testRandomAccess);
  CPPUNIT_TEST_SUITE_END();

private:
  static unsigned char SIV_KEYS[32];
  sbdi_t *sbdi;
  mt_hash_t root;
  int fd;
  sbdi_pio_t *pio;

  void loadStore()
  {
    fd = open(FILE_NAME, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    CPPUNIT_ASSERT(fd != -1);
    struct stat s;
    CPPUNIT_ASSERT(fstat(fd, &s) == 0);
    pio = sbdi_pio_create(&fd, s.st_size);
    CPPUNIT_ASSERT(sbdi_open(&sbdi, pio, SBDI_CRYPTO_NONE, SIV_KEYS, root) == SBDI_SUCCESS);
  }

  void closeStore()
  {
    CPPUNIT_ASSERT(sbdi_close(sbdi, SIV_KEYS, root) == SBDI_SUCCESS);
    int fd = *(int *) pio->iod;
    CPPUNIT_ASSERT(close(fd) != -1);
    sbdi_pio_delete(pio);
  }

  void deleteStore()
  {
    memset(root, 0, sizeof(mt_hash_t));
    CPPUNIT_ASSERT(unlink(FILE_NAME) != -1);
  }

  void read(unsigned char *buf, size_t len, off_t off)
  {
    ssize_t rd = 0;
    sbdi_error_t r = sbdi_pread(&rd, sbdi, buf, len, off);
    if (r != SBDI_SUCCESS) {
      std::cout << "Reading file @ offset " << off << ". Error: "
          << err_to_string(r) << std::endl;
    }
    CPPUNIT_ASSERT(r == SBDI_SUCCESS);
  }

  void write(unsigned char *buf, size_t len, off_t off)
  {
    ssize_t wr = 0;
    sbdi_error_t r = sbdi_pwrite(&wr, sbdi, buf, len, off);
    if (r != SBDI_SUCCESS) {
      std::cout << "Writing file @ offset " << off << ". Error: "
          << err_to_string(r) << std::endl;
    }
    CPPUNIT_ASSERT(r == SBDI_SUCCESS);
  }

  void fill(uint32_t c, unsigned char *buf, size_t len)
  {
    CPPUNIT_ASSERT(c <= UINT8_MAX);
    for (size_t i = 0; i < len; ++i, ++c) {
      buf[i] = c % UINT8_MAX;
    }
  }

  void cmp(uint32_t c, unsigned char *buf, size_t len)
  {
    CPPUNIT_ASSERT(c <= UINT8_MAX);
    for (size_t i = 0; i < len; ++i, ++c) {
      if (buf[i] != c % UINT8_MAX) {
        std::cout << "Comparison @ offset " << i << " fails." << std::endl;
      }
      CPPUNIT_ASSERT(buf[i] == c % UINT8_MAX);
    }
  }

  void f_write(uint32_t v, unsigned char *buf, size_t len, off_t off)
  {
    fill(v, buf, len);
    write(buf, len, off);
  }

  void c_read(uint32_t v, unsigned char *buf, size_t len, off_t off)
  {
    memset(buf, 0xFF, len);
    read(buf, len, off);
    cmp(v, buf, len);
  }

public:
  void setUp()
  {
    unlink(FILE_NAME);
    memset(root, 0, sizeof(mt_hash_t));
  }

  void tearDown()
  {

  }

  void testParameterChecks()
  {
    loadStore();
    ssize_t rd = 0;
    off_t of = 0;
    uint8_t d[2] = { 42, 23 };
    ASS_ERR_ILL_PAR(sbdi_read(NULL, NULL, NULL, SBDI_SIZE_MAX + 1));
    ASS_ERR_ILL_PAR(sbdi_read(&rd, NULL, NULL, SBDI_SIZE_MAX + 1));
    ASS_ERR_ILL_PAR(sbdi_read(&rd, sbdi, NULL, SBDI_SIZE_MAX + 1));
    ASS_ERR_ILL_PAR(sbdi_read(&rd, sbdi, d, SBDI_SIZE_MAX + 1));
    ASS_SUC(sbdi_read(&rd, sbdi, d, 1));
    CPPUNIT_ASSERT(rd == 0 && d[0] == 42);
    ASS_ERR_ILL_PAR(sbdi_write(NULL, NULL, NULL, SBDI_SIZE_MAX + 1));
    ASS_ERR_ILL_PAR(sbdi_write(&rd, NULL, NULL, SBDI_SIZE_MAX + 1));
    ASS_ERR_ILL_PAR(sbdi_write(&rd, sbdi, NULL, SBDI_SIZE_MAX + 1));
    ASS_ERR_ILL_PAR(sbdi_write(&rd, sbdi, d, SBDI_SIZE_MAX + 1));
    ASS_SUC(sbdi_write(&rd, sbdi, d, 1));
    ASS_SUC(sbdi_lseek(&of, sbdi, 0, SBDI_SEEK_SET));
    ASS_SUC(sbdi_read(&rd, sbdi, d, 1));
    CPPUNIT_ASSERT(rd == 1 && d[0] == 42);
    ASS_ERR_ILL_PAR(sbdi_lseek(NULL, NULL, SBDI_SIZE_MAX + 1, SBDI_SEEK_SET));
    ASS_ERR_ILL_PAR(sbdi_lseek(&of, NULL, SBDI_SIZE_MAX + 1, SBDI_SEEK_SET));
    ASS_ERR_ILL_PAR(sbdi_lseek(NULL, sbdi, SBDI_SIZE_MAX + 1, SBDI_SEEK_SET));
    ASS_ERR_ILL_PAR(sbdi_lseek(&of, sbdi, SBDI_SIZE_MAX + 1, SBDI_SEEK_SET));
    ASS_SUC(sbdi_lseek(&of, sbdi, SBDI_SIZE_MAX-1, SBDI_SEEK_SET));
    // NOTE: This check fails on 32 bit systems, because the overflow detection is triggered
    ASS_SUC(sbdi_write(&rd, sbdi, d, 1));
    ASS_SUC(sbdi_lseek(&of, sbdi, SBDI_SIZE_MAX-1, SBDI_SEEK_SET));
    ASS_SUC(sbdi_read(&rd, sbdi, d, 1));
    CPPUNIT_ASSERT(rd == 1 && d[0] == 42);
    ASS_SUC(sbdi_lseek(&of, sbdi, SBDI_SIZE_MAX-1, SBDI_SEEK_SET));
    ASS_ERR_ILL_PAR(sbdi_lseek(&of, sbdi, 1, SBDI_SEEK_CUR));
    ASS_SUC(sbdi_lseek(&of, sbdi, 0, SBDI_SEEK_CUR));
    ASS_SUC(sbdi_write(&rd, sbdi, d, 2));
    CPPUNIT_ASSERT(rd == 1);
    ASS_ERR_ILL_PAR(sbdi_lseek(&of, sbdi, 1, SBDI_SEEK_END));
    ASS_ERR_ILL_PAR(sbdi_lseek(&of, sbdi, 0, SBDI_SEEK_END));
    closeStore();
    deleteStore();
  }
  void testSimpleReadWrite()
  {
    loadStore();
    unsigned char *b = (unsigned char *) malloc(
        sizeof(unsigned char) * 1024 * 1024);
    f_write(17, b, 5 * 1024, 34);
    c_read(17, b, 5 * 1024, 34);
    CPPUNIT_ASSERT(sbdi_fsync(sbdi, SIV_KEYS) == SBDI_SUCCESS);
    closeStore();
    loadStore();
    c_read(17, b, 5 * 1024, 34);
    closeStore();
    deleteStore();
    free(b);
  }

  void testReadWriteUpdate()
  {
    loadStore();
    closeStore();
    deleteStore();
  }

  void testRandomAccess()
  {
    loadStore();
    const int BLK_SIZE = 1 * 1024;
    const int BLKS = 2048;
    unsigned char *b = (unsigned char *) malloc(
        sizeof(unsigned char) * BLK_SIZE);
    CPPUNIT_ASSERT(b);
    //==== Sequential Setup Phase ====
    for (int i = 0; i < BLKS; ++i) {
      f_write(i % 256, b, BLK_SIZE, i * BLK_SIZE);
    }
    for (int i = 0; i < BLKS; ++i) {
      c_read(i % 256, b, BLK_SIZE, i * BLK_SIZE);
    }

    //==== Random Write Test ====
    std::vector<int> idxs;
    for (int i = 0; i < BLKS; ++i) {
      idxs.push_back(i);
    }
    std::random_shuffle(idxs.begin(), idxs.end());
    for (int i = 0; i < BLKS; ++i) {
      f_write(i % 256, b, BLK_SIZE, idxs.at(i) * BLK_SIZE);
    }
    for (int i = 0; i < BLKS; ++i) {
      c_read(i % 256, b, BLK_SIZE, idxs.at(i) * BLK_SIZE);
    }
    closeStore();
    deleteStore();
    free(b);
  }
};

unsigned char SbdiTest::SIV_KEYS[32] = {
    // Part 1: fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
    0xf3, 0xf2, 0xf1, 0xf0,
    // Part 2: f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff };

CPPUNIT_TEST_SUITE_REGISTRATION(SbdiTest);
