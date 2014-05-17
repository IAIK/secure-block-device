/*
 * SbdiCtrTest.cpp
 *
 *  Created on: May 15, 2014
 *      Author: dhein
 */

#include <cppunit/extensions/HelperMacros.h>

#include "sbdi_cache.h"

#include <string.h>

#ifndef UINT32_MAX
#include <limits>
#define UINT32_MAX std::numeric_limits<uint32_t>::max()
#endif

class SbdiCacheTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE( SbdiCacheTest );
  CPPUNIT_TEST(testCacheAndFind);
  CPPUNIT_TEST(testOverfillCache);
  CPPUNIT_TEST(testUpdateCache);
  CPPUNIT_TEST(testParamChecks);
  CPPUNIT_TEST_SUITE_END();

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

public:
  void setUp()
  {
    cache = sbdi_bc_cache_create();
  }

  void tearDown()
  {
    sbdi_bc_cache_destroy(cache);
  }

  void testCacheAndFind()
  {
    sbdi_block_t *blk = NULL;
    sbdi_block_t *c_blk = NULL;
    CPPUNIT_ASSERT(sbdi_bc_cache_blk(cache, 26, &blk) == SBDI_SUCCESS);
    memset(blk, 0x11, SBDI_BLOCK_SIZE);
    CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, 26, &c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!memcmp(blk, c_blk, SBDI_BLOCK_SIZE));
    blk = NULL;
    CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, 42, &blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(blk == NULL);
  }

  void testOverfillCache()
  {
    sbdi_block_t *blk = NULL;
    sbdi_block_t *c_blk = NULL;
    for (uint32_t i = 0x10; i < (0x10 + SBDI_CACHE_MAX_SIZE + 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_cache_blk(cache, i, &blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk != NULL);
      memset(blk, i, SBDI_BLOCK_SIZE);
    }
    CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, 0x10, &c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk == NULL);
    CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, 0x11, &c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk == NULL);
    for (uint32_t i = 0x12; i < (0x10 + SBDI_CACHE_MAX_SIZE + 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, i, &c_blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(c_blk != NULL);
      CPPUNIT_ASSERT(memchrcmp(*c_blk, i, SBDI_BLOCK_SIZE));
    }
  }

  void testUpdateCache()
  {
    sbdi_block_t *blk = NULL;
    sbdi_block_t *c_blk = NULL;
    for (uint32_t i = 0x10; i < (0x10 + SBDI_CACHE_MAX_SIZE); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_cache_blk(cache, i, &blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk != NULL);
      memset(blk, i, SBDI_BLOCK_SIZE);
    }
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk(cache, 0x10+SBDI_CACHE_MAX_SIZE-1, &c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(*c_blk, 0x10+SBDI_CACHE_MAX_SIZE-1, SBDI_BLOCK_SIZE));
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk(cache, 0x10+SBDI_CACHE_MAX_SIZE-2, &c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(*c_blk, 0x10+SBDI_CACHE_MAX_SIZE-2, SBDI_BLOCK_SIZE));
    for (uint32_t i = 0x20; i < (0x20 + SBDI_CACHE_MAX_SIZE - 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_cache_blk(cache, i, &blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk != NULL);
      memset(blk, i, SBDI_BLOCK_SIZE);
    }
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk(cache, 0x10+SBDI_CACHE_MAX_SIZE-1, &c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(*c_blk, 0x10+SBDI_CACHE_MAX_SIZE-1, SBDI_BLOCK_SIZE));
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk(cache, 0x10+SBDI_CACHE_MAX_SIZE-2, &c_blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(c_blk != NULL);
    CPPUNIT_ASSERT(
        memchrcmp(*c_blk, 0x10+SBDI_CACHE_MAX_SIZE-2, SBDI_BLOCK_SIZE));
    for (uint32_t i = 0x10; i < (0x10 + SBDI_CACHE_MAX_SIZE-2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, i, &blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk == NULL);
    }
    for (uint32_t i = 0x20; i < (0x20 + SBDI_CACHE_MAX_SIZE - 2); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, i, &blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk != NULL);
      memset(blk, i, SBDI_BLOCK_SIZE);
    }
  }

  void testParamChecks()
  {
    sbdi_block_t *blk;
    CPPUNIT_ASSERT(sbdi_bc_cache_blk(NULL, 0, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(sbdi_bc_cache_blk(cache, 0, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_cache_blk(cache, UINT32_MAX, &blk) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(sbdi_bc_find_blk(NULL, 0, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, 0, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk(cache, UINT32_MAX, &blk) == SBDI_ERR_ILLEGAL_PARAM);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(SbdiCacheTest);
