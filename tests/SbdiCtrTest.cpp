///
/// \file
/// \brief Tests the 128-bit counter used by the Secure Block Device Library.
///

#include "sbdi_ctr_128b.h"

#include <cppunit/extensions/HelperMacros.h>

#ifndef UINT64_C
#define UINT64_C(c) c ## ULL
#endif
#ifndef UINT64_MAX
#include <limits>
#define UINT64_MAX std::numeric_limits<uint64_t>::max()
#endif

#define TP_1 UINT64_C(0xFFEEDDCCBBAA9988)
#define TP_2 UINT64_C(0x7766554433221100)


class SbdiCtrTest: public CppUnit::TestFixture {
CPPUNIT_TEST_SUITE( SbdiCtrTest );
  CPPUNIT_TEST(testInit);
  CPPUNIT_TEST(testReset);
  CPPUNIT_TEST(testBasicIncrement);
  CPPUNIT_TEST(testBorderIncrement);
  CPPUNIT_TEST_SUITE_END();

private:
  static const sbdi_ctr_128b_t ZERO;
  static const sbdi_ctr_128b_t ONE;
  static const sbdi_ctr_128b_t TWO;
  static const sbdi_ctr_128b_t LO_MAX;
  static const sbdi_ctr_128b_t ONE_ZERO;
  static const sbdi_ctr_128b_t MAX_LO_MAX;
  static const sbdi_ctr_128b_t MAX_M1;
  static const sbdi_ctr_128b_t MAX;

public:
  void setUp()
  {
  }

  void tearDown()
  {

  }

  void testInit()
  {
    sbdi_ctr_128b_t tst;
    sbdi_ctr_128b_init(&tst, TP_1, TP_2);
    CPPUNIT_ASSERT(tst.hi == TP_1);
    CPPUNIT_ASSERT(tst.lo == TP_2);
  }

  void testReset()
  {
    sbdi_ctr_128b_t tst;
    tst.hi = TP_1;
    tst.lo = TP_2;
    sbdi_ctr_128b_reset(&tst);
    CPPUNIT_ASSERT(tst.hi == 0);
    CPPUNIT_ASSERT(tst.lo == 0);
  }

  void testBasicIncrement()
  {
    int res = 0;
    sbdi_ctr_128b_t tst;
    sbdi_ctr_128b_reset(&tst);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &ZERO, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
    sbdi_ctr_128b_inc(&tst);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &ONE, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
    sbdi_ctr_128b_inc(&tst);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &TWO, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
  }

  void testBorderIncrement() {
    int res = 0;
    sbdi_ctr_128b_t tst, cmp;
    CPPUNIT_ASSERT(sbdi_ctr_128b_init(&tst, UINT64_MAX - 1, UINT64_MAX) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(sbdi_ctr_128b_init(&cmp, UINT64_MAX, 0) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &MAX_LO_MAX, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
    CPPUNIT_ASSERT(sbdi_ctr_128b_inc(&tst) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &cmp, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
    CPPUNIT_ASSERT(sbdi_ctr_128b_init(&tst, 0, UINT64_MAX) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &ONE_ZERO, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
    CPPUNIT_ASSERT(sbdi_ctr_128b_init(&tst, UINT64_MAX, UINT64_MAX-1) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &MAX_M1, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
    CPPUNIT_ASSERT(sbdi_ctr_128b_inc(&tst) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &MAX, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
    CPPUNIT_ASSERT(sbdi_ctr_128b_inc(&tst) == SBDI_ERR_ILLEGAL_STATE);
    CPPUNIT_ASSERT(sbdi_ctr_128b_cmp(&tst, &MAX, &res) == SBDI_SUCCESS);
    CPPUNIT_ASSERT(!res);
  }

};

const sbdi_ctr_128b_t SbdiCtrTest::ZERO = { 0, 0 };
const sbdi_ctr_128b_t SbdiCtrTest::ONE = { 0, 1 };
const sbdi_ctr_128b_t SbdiCtrTest::TWO = { 0, 2 };
const sbdi_ctr_128b_t SbdiCtrTest::LO_MAX = { 0, UINT64_MAX };
const sbdi_ctr_128b_t SbdiCtrTest::ONE_ZERO = { 0, UINT64_MAX };
const sbdi_ctr_128b_t SbdiCtrTest::MAX_LO_MAX = { UINT64_MAX - 1, UINT64_MAX };
const sbdi_ctr_128b_t SbdiCtrTest::MAX_M1 = { UINT64_MAX, UINT64_MAX - 1 };
const sbdi_ctr_128b_t SbdiCtrTest::MAX = { UINT64_MAX, UINT64_MAX };

CPPUNIT_TEST_SUITE_REGISTRATION(SbdiCtrTest);
