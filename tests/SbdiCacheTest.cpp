///
/// \file
/// \brief Tests the Secure Block Device Library's data cache.
///
#include <cppunit/extensions/HelperMacros.h>

#ifndef UINT32_MAX
#include <limits>
#define UINT32_MAX std::numeric_limits<uint32_t>::max()
#endif
#ifndef UINT32_C
#define UINT32_C(c) c ## u
#endif
#ifndef UINT8_MAX
#define UINT8_MAX 256u
#endif
#ifndef UINT16_MAX
#define UINT16_MAX 65536u
#endif

#include "SbdiTest.h"

#include "sbdi_cache.h"

#include <string.h>

#include <set>

class SbdiCacheTest: public CppUnit::TestFixture {
CPPUNIT_TEST_SUITE( SbdiCacheTest );
  CPPUNIT_TEST(testCacheAndFind);
  CPPUNIT_TEST(testOverfillCache);
  CPPUNIT_TEST(testUpdateCache);
  CPPUNIT_TEST(testEvict);
  CPPUNIT_TEST(testSync);
  CPPUNIT_TEST(testComplexSync);
  CPPUNIT_TEST(testParamChecks);CPPUNIT_TEST_SUITE_END()
  ;

private:
  sbdi_bc_t *cache;
  std::set<uint32_t> exp_sync;

  sbdi_error_t sbdi_bc_cache_blk_i(uint32_t idx, sbdi_block_t *blk)
  {
    blk->idx = idx;
    sbdi_error_t r = sbdi_bc_cache_blk(cache, blk, SBDI_BC_BT_DATA);
    if (r != SBDI_SUCCESS) {
      std::cout << err_to_string(r) << std::endl;
    }
    return r;
  }

  sbdi_error_t sbdi_bc_find_blk_i(uint32_t idx, sbdi_block_t *blk)
  {
    blk->idx = idx;
    return sbdi_bc_find_blk(cache, blk);
  }

  static sbdi_error_t sync_cb(void *sync_data, sbdi_block_t *blk)
  {
    std::set<uint32_t> &exp_sync = *((std::set<uint32_t>*) sync_data);
    std::cout << "Sync block " << blk->idx << " @ " << blk->data << std::endl;
    if (exp_sync.find(blk->idx) == exp_sync.end()) {
      std::cout << "Unexpected sync: " << blk->idx << " @ " << blk->data
          << std::endl;
      return SBDI_ERR_ILLEGAL_PARAM;
    } else {
      exp_sync.erase(blk->idx);
      return SBDI_SUCCESS;
    }
  }

  static int is_in_scope(const uint32_t mng, const uint32_t blk)
  {
    return blk > mng && blk <= (mng + SBDI_MNGT_BLOCK_ENTRIES);
  }

public:
  void setUp()
  {
    cache = sbdi_bc_cache_create(&exp_sync, &sync_cb, &is_in_scope);
    exp_sync.clear();
  }

  void tearDown()
  {
    exp_sync.clear();
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

  void testEvict()
  {
    sbdi_block_t blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_invalidate(blk);
    for (uint32_t i = 0x40; i < (0x40 + SBDI_CACHE_MAX_SIZE); ++i) {
      CPPUNIT_ASSERT(sbdi_bc_cache_blk_i(i, blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(blk->data != NULL);
      memset(blk->data, i, SBDI_BLOCK_SIZE);
    }
    sbdi_block_init(blk, 0x42, NULL);
    CPPUNIT_ASSERT(sbdi_bc_evict_blk(cache, blk->idx) == SBDI_SUCCESS);
    sbdi_block_init(blk, 0x07, NULL);
    CPPUNIT_ASSERT(sbdi_bc_cache_blk_i(0x07, blk) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(memchrcmp(*blk->data, 0x42, SBDI_BLOCK_SIZE));
    for (uint32_t i = 0x40; i < (0x40 + SBDI_CACHE_MAX_SIZE); ++i) {
      if (i == 0x42) {
        continue;
      }
      CPPUNIT_ASSERT(sbdi_bc_find_blk_i(i, blk) == SBDI_SUCCESS);
      CPPUNIT_ASSERT(memchrcmp(*blk->data, i, SBDI_BLOCK_SIZE));
    }
    CPPUNIT_ASSERT(
        (sbdi_bc_find_blk_i(0x07, blk) == SBDI_SUCCESS) && (blk->data != NULL));
    sbdi_block_init(blk, 0x11, NULL);
    CPPUNIT_ASSERT(
        sbdi_bc_dirty_blk(cache, blk->idx) == SBDI_ERR_ILLEGAL_STATE);
  }

  void testSync()
  {
    sbdi_block_t blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_invalidate(blk);
    for (uint32_t i = 0x50; i < (0x50 + SBDI_CACHE_MAX_SIZE); ++i) {
      sbdi_block_init(blk, i, NULL);
      if (i == 0x50) {
        ASS_SUC(sbdi_bc_cache_blk(cache, blk, SBDI_BC_BT_MNGT));
      } else {
        ASS_SUC(sbdi_bc_cache_blk(cache, blk, SBDI_BC_BT_DATA));
      }
      CPPUNIT_ASSERT(blk->data != NULL);
      memset(blk->data, i, SBDI_BLOCK_SIZE);
    }
    sbdi_block_init(blk, 0x50, NULL);
    ASS_SUC(sbdi_bc_dirty_blk(cache, blk->idx));
    sbdi_block_init(blk, 0x51, NULL);
    ASS_SUC(sbdi_bc_dirty_blk(cache, blk->idx));
    sbdi_block_init(blk, 0x52, NULL);
    ASS_SUC(sbdi_bc_dirty_blk(cache, blk->idx));
    exp_sync.insert(exp_sync.begin(), 0x51);
    sbdi_block_init(blk, 0x60, NULL);
    ASS_SUC(sbdi_bc_cache_blk(cache, blk, SBDI_BC_BT_MNGT));
    CPPUNIT_ASSERT(exp_sync.size() == 0);
    exp_sync.clear();
    // No sync should happen!
    exp_sync.insert(exp_sync.begin(), 0x50);
    exp_sync.insert(exp_sync.begin(), 0x52);
    ASS_SUC(sbdi_bc_sync(cache));
    CPPUNIT_ASSERT(exp_sync.size() == 0);
    exp_sync.clear();
  }

  void cacheBlock(sbdi_block_t *blk, uint32_t idx, sbdi_bc_bt_t type)
  {
    sbdi_block_invalidate(blk);
    sbdi_block_init(blk, idx, NULL);
    CPPUNIT_ASSERT(sbdi_bc_cache_blk(cache, blk, type) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(blk->data != NULL);
    memset(blk->data, idx, SBDI_BLOCK_SIZE);
  }

  void initComplexSyncCache(uint32_t s_idx, uint32_t e_idx)
  {
    sbdi_block_t blk;
    cacheBlock(&blk, s_idx, SBDI_BC_BT_MNGT);
    for (uint32_t i = s_idx + 1; i < e_idx; ++i) {
      cacheBlock(&blk, i, SBDI_BC_BT_DATA);
    }
  }

  void complexSyncDirtyBlocks(uint32_t s_idx, uint32_t e_idx)
  {
    sbdi_block_t blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_invalidate(blk);
    for (uint32_t i = s_idx; i < e_idx; ++i) {
      if (i % 2) {
        continue;
      }
      sbdi_block_init(blk, i, NULL);
      ASS_SUC(sbdi_bc_dirty_blk(cache, blk->idx));
    }
  }

  void testComplexSync()
  {
    sbdi_block_t blk;
    initComplexSyncCache(0x00, (SBDI_CACHE_MAX_SIZE / 2));
    initComplexSyncCache(0x80, 0x80 + (SBDI_CACHE_MAX_SIZE / 2));
    complexSyncDirtyBlocks(0x00, (SBDI_CACHE_MAX_SIZE / 2));
    complexSyncDirtyBlocks(0x80, 0x80 + (SBDI_CACHE_MAX_SIZE / 2));
    cacheBlock(&blk, 0x200, SBDI_BC_BT_DATA);
    exp_sync.insert(exp_sync.begin(), 0x02);
    cacheBlock(&blk, 0x201, SBDI_BC_BT_DATA);
    CPPUNIT_ASSERT(exp_sync.size() == 0);
    exp_sync.clear();
  }

  void testParamChecks()
  {
    sbdi_block_t blk_dat;
    sbdi_block_t *blk = &blk_dat;
    sbdi_block_invalidate(blk);
    CPPUNIT_ASSERT(
        sbdi_bc_cache_blk(NULL, NULL, SBDI_BC_BT_DATA) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_cache_blk(cache, NULL, SBDI_BC_BT_DATA) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_cache_blk(cache, blk, SBDI_BC_BT_RESV)
            == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_cache_blk_i(UINT32_MAX, blk) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(sbdi_bc_find_blk(NULL, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(sbdi_bc_find_blk(cache, NULL) == SBDI_ERR_ILLEGAL_PARAM);
    CPPUNIT_ASSERT(
        sbdi_bc_find_blk_i(UINT32_MAX, blk) == SBDI_ERR_ILLEGAL_PARAM);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(SbdiCacheTest);
