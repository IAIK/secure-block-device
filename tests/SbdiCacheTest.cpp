/*
 * SbdiCtrTest.cpp
 *
 *  Created on: May 15, 2014
 *      Author: dhein
 */

#include <cppunit/extensions/HelperMacros.h>

#ifndef UINT32_MAX
#include <limits>
#define UINT32_MAX std::numeric_limits<uint32_t>::max()
#endif

#include "sbdi_cache.h"

#include <string.h>

class SbdiCacheTest: public CppUnit::TestFixture {
CPPUNIT_TEST_SUITE( SbdiCacheTest );
  CPPUNIT_TEST(testCacheAndFind);
  CPPUNIT_TEST(testOverfillCache);
  CPPUNIT_TEST(testUpdateCache);
  CPPUNIT_TEST(testParamChecks);CPPUNIT_TEST_SUITE_END()
  ;

private:
  sbdi_bc_t *cache;

  int memchrcmp(unsigned char *buffer, int chr, size_t len)
  {
    for (size_t i = 0; i < len; ++i) {
      if (buffer[i] != (unsigned char) chr) {
        return 0;
      }
    }
    return 1;
  }

  sbdi_error_t sbdi_bc_cache_blk_i(uint32_t idx, sbdi_block_t *blk)
  {
    blk->idx = idx;
    return sbdi_bc_cache_blk(cache, blk);
  }

  sbdi_error_t sbdi_bc_find_blk_i(uint32_t idx, sbdi_block_t *blk)
  {
    blk->idx = idx;
    return sbdi_bc_find_blk(cache, blk);
  }

  static sbdi_error_t sync_cb(sbdi_block_t *blk) {
    std::cout << "Evict block " << blk->idx  << " @ " << blk->data << std::endl;
    return SBDI_SUCCESS;
  }

public:
  void setUp()
  {
    cache = sbdi_bc_cache_create(&sync_cb);
  }

  void tearDown()
  {
    sbdi_bc_cache_destroy(cache);
  }

  void testCacheAndFind()
  {
    sbdi_block_t blk_dat, c_blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_t *c_blk = &c_blk_dat;
    sbdi_block_invalidate(blk);
    sbdi_block_invalidate(c_blk);
    CPPUNIT_ASSERT(sbdi_bc_cache_blk_i(26, blk) == SBDI_SUCCESS);
    memset(blk->data, 0x11, SBDI_BLOCK_SIZE);
    CPPUNIT_ASSERT(sbdi_bc_find_blk_i(26, c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(blk->data == c_blk->data);
    blk->data = NULL;
    CPPUNIT_ASSERT(sbdi_bc_find_blk_i(42, blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(blk->data == NULL);
  }

  void testOverfillCache()
  {
    sbdi_block_t blk_dat, c_blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_t *c_blk = &c_blk_dat;
    sbdi_block_invalidate(blk);
    sbdi_block_invalidate(c_blk);
    for (uint32_t i = 0x10; i < (0x10 + SBDI_CACHE_MAX_SIZE + 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_cache_blk_i(i, blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk->data != NULL);
      memset(blk->data, i, SBDI_BLOCK_SIZE);
    }
    CPPUNIT_ASSERT(sbdi_bc_find_blk_i(0x10, c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk->data == NULL);
    CPPUNIT_ASSERT(sbdi_bc_find_blk_i(0x11, c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk->data == NULL);
    for (uint32_t i = 0x12; i < (0x10 + SBDI_CACHE_MAX_SIZE + 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_find_blk_i(i, c_blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(c_blk->data != NULL);
      CPPUNIT_ASSERT(memchrcmp(c_blk->data[0], i, SBDI_BLOCK_SIZE));
    }
  }

  void testUpdateCache()
  {
    sbdi_block_t blk_dat, c_blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_t *c_blk = &c_blk_dat;
    sbdi_block_invalidate(blk);
    sbdi_block_invalidate(c_blk);
    for (uint32_t i = 0x10; i < (0x10 + SBDI_CACHE_MAX_SIZE); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_cache_blk_i(i, blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk->data != NULL);
      memset(blk->data, i, SBDI_BLOCK_SIZE);
    }
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk_i(0x10+SBDI_CACHE_MAX_SIZE-1, c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk->data != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(*c_blk->data, 0x10+SBDI_CACHE_MAX_SIZE-1, SBDI_BLOCK_SIZE));
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk_i(0x10+SBDI_CACHE_MAX_SIZE-2, c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk->data != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(c_blk->data[0], 0x10+SBDI_CACHE_MAX_SIZE-2, SBDI_BLOCK_SIZE));
    for (uint32_t i = 0x20; i < (0x20 + SBDI_CACHE_MAX_SIZE - 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_cache_blk_i(i, blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk->data != NULL);
      memset(blk->data, i, SBDI_BLOCK_SIZE);
    }
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk_i(0x10+SBDI_CACHE_MAX_SIZE-1, c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk->data != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(c_blk->data[0], 0x10+SBDI_CACHE_MAX_SIZE-1, SBDI_BLOCK_SIZE));
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk_i(0x10+SBDI_CACHE_MAX_SIZE-2, c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk->data != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(*c_blk->data, 0x10+SBDI_CACHE_MAX_SIZE-2, SBDI_BLOCK_SIZE));
    for (uint32_t i = 0x10; i < (0x10 + SBDI_CACHE_MAX_SIZE - 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_find_blk_i(i, blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk->data == NULL);
    }
    for (uint32_t i = 0x20; i < (0x20 + SBDI_CACHE_MAX_SIZE - 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_find_blk_i(i, blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk->data != NULL);
      memset(blk->data, i, SBDI_BLOCK_SIZE);
    }
  }

  void testParamChecks()
  {
    sbdi_block_t blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_invalidate(blk);
    CPPUNIT_ASSERT(sbdi_bc_cache_blk(NULL, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(sbdi_bc_cache_blk(cache, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_cache_blk_i(UINT32_MAX, blk) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(sbdi_bc_find_blk(NULL, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk(cache, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk_i(UINT32_MAX, blk) == SBDI_ERR_ILLEGAL_PARAM);
  }

  // TODO test evict function!
  // TODO test sync function!
};

CPPUNIT_TEST_SUITE_REGISTRATION(SbdiCacheTest);
