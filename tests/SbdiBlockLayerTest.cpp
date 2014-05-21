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

#include "sbdi_block.h"

#include <cppunit/extensions/HelperMacros.h>

class SbdiBLockLayerTest: public CppUnit::TestFixture {
CPPUNIT_TEST_SUITE( SbdiBLockLayerTest );
  CPPUNIT_TEST(testIndexComp);CPPUNIT_TEST_SUITE_END()
  ;

private:

public:
  void setUp()
  {
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
    }
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(SbdiBLockLayerTest);
