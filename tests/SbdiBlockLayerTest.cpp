/*
 * SbdiBLockLayerTest.cpp
 *
 *  Created on: May 21, 2014
 *      Author: dhein
 */

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

#include "sbdi.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <cppunit/extensions/HelperMacros.h>

#define SIV_KEY_LEN 256
#define FILE_NAME "sbdi_tst_enc"

class SbdiBLockLayerTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE( SbdiBLockLayerTest );
  CPPUNIT_TEST(testIndexComp);
  CPPUNIT_TEST(testSimpleReadWrite);
  CPPUNIT_TEST(testExtendedReadWrite);
  CPPUNIT_TEST_SUITE_END();

private:
  static unsigned char SIV_KEYS[32];
  sbdi_t *sbdi;
  unsigned char b[SBDI_BLOCK_SIZE];

  void loadStore()
  {
    int fd = open(FILE_NAME, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    CPPUNIT_ASSERT(fd != -1);
    sbdi = sbdi_create(fd, SIV_KEYS, SIV_KEY_LEN);
    CPPUNIT_ASSERT(sbdi != NULL);
  }

  void closeStore()
  {
    CPPUNIT_ASSERT(close(sbdi->fd) != -1);
    sbdi_delete(sbdi);
  }

  void deleteStore() {
    CPPUNIT_ASSERT(unlink(FILE_NAME) != -1);
  }

public:
  void setUp()
  {
    memset(b, 0, SBDI_BLOCK_SIZE);
  }

  void tearDown()
  {

  }

  void testIndexComp()
  {
    for (uint32_t log_idx = 0; log_idx < SBDI_BLOCK_MAX_INDEX; ++log_idx) {
      uint32_t phy_idx = sbdi_get_data_block_index(log_idx);
      if (log_idx != sbdi_bl_idx_phy_to_log(phy_idx)) {
        std::cout << "log: " << log_idx << " phy: " << phy_idx << " phy(log): "
            << sbdi_bl_idx_phy_to_log(phy_idx) << std::endl;
        CPPUNIT_ASSERT(0);
      }
      uint32_t mng_log_idx = sbdi_get_mngt_block_index(log_idx);
      uint32_t mng_phy_idx = sbdi_bl_idx_phy_to_mng(phy_idx);
      if (mng_log_idx != mng_phy_idx) {
        std::cout << "log: " << log_idx << " phy: " << phy_idx << " mng(log): "
            << mng_log_idx << " mng(phy) " << mng_phy_idx << std::endl;
        CPPUNIT_ASSERT(0);
      }
      uint32_t mng_log_blk_nbr = sbdi_get_mngt_block_number(log_idx);
      uint32_t mng_phy_blk_nbr = sbdi_bl_mng_phy_to_mng_log(mng_phy_idx);
      if (mng_log_blk_nbr != mng_phy_blk_nbr) {
        std::cout << "log: " << log_idx << " phy: " << phy_idx
            << " mng_nbr(log): " << mng_log_blk_nbr << " mng_nbr(phy) "
            << mng_phy_blk_nbr << std::endl;
        CPPUNIT_ASSERT(0);
      }
    }
  }

  void read(uint32_t i) {
    sbdi_error_t r = sbdi_bl_read_data_block(sbdi, b, i, SBDI_BLOCK_SIZE);
    CPPUNIT_ASSERT(r == SBDI_SUCCESS);
  }

  void write(uint32_t i) {
    sbdi_error_t r = sbdi_bl_write_data_block(sbdi, b, i, SBDI_BLOCK_SIZE);
    CPPUNIT_ASSERT(r == SBDI_SUCCESS);
  }

  void fill(uint32_t c) {
    CPPUNIT_ASSERT(c <= UINT8_MAX);
    memset(b, c, SBDI_BLOCK_SIZE);
  }

  void f_write(uint32_t i, uint32_t v) {
    fill(v);
    write(i);
  }

  void cmp(uint32_t c) {
    CPPUNIT_ASSERT(c <= UINT8_MAX);
    CPPUNIT_ASSERT(memchrcmp(b, c, 4096));
  }

  void c_read(uint32_t i, uint32_t v) {
    fill(0xFF);
    read(i);
    cmp(v);
  }

  void testSimpleReadWrite()
  {
    loadStore();
    f_write(0, 0x10);
    c_read(0, 0x10);
    f_write(1, 0x11);
    c_read(1, 0x11);
    CPPUNIT_ASSERT(sbdi_bc_sync(sbdi->cache) == SBDI_SUCCESS);
    closeStore();
    loadStore();
    c_read(1, 0x11);
    c_read(0, 0x10);
    closeStore();
    deleteStore();
  }

  void testExtendedReadWrite() {
    loadStore();
    f_write(0x80, 0x80);
    c_read(0x80, 0x80);
//    CPPUNIT_ASSERT(sbdi_bl_read_data_block(sbdi, buf, 0, 4096) == SBDI_SUCCESS);
//    CPPUNIT_ASSERT(memchrcmp(buf, 0x80, 4096));
//    CPPUNIT_ASSERT(
//        sbdi_bl_read_data_block(sbdi, buf, 128, 4096) == SBDI_SUCCESS);
//    CPPUNIT_ASSERT(memchrcmp(buf, 0xF3, 4096));
//    write(2049);
    closeStore();
    deleteStore();
  }
};

unsigned char SbdiBLockLayerTest::SIV_KEYS[32] = {
    // Part 1: fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
    0xf3, 0xf2, 0xf1, 0xf0,
    // Part 2: f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff };

CPPUNIT_TEST_SUITE_REGISTRATION(SbdiBLockLayerTest);
