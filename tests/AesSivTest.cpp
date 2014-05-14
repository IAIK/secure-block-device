/*
 * AesSivTest.cpp
 *
 *  Created on: May 14, 2014
 *      Author: dhein
 */
#include "crypto/siv.h"

#include <string>

#include <cppunit/extensions/HelperMacros.h>

class AesSivTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE( AesSivTest );
  CPPUNIT_TEST( testSivEncryption );
  CPPUNIT_TEST_SUITE_END();

private:
  static unsigned char SIV_KEYS[32];

  static unsigned char PLAIN_TEXT[16];

  static unsigned char AD_H1[24];

  siv_ctx ctx;
  unsigned char CIPHER_TEXT[16];
  unsigned char IV[16];

public:
  void setUp()
  {
    siv_init(&ctx, SIV_KEYS, SIV_256);
  }

  void tearDown()
  {
    siv_restart(&ctx);
  }

  void testSivEncryption()
  {
    siv_encrypt(&ctx, PLAIN_TEXT, CIPHER_TEXT, 14, IV, 1, AD_H1, 24);
  }

};

unsigned char AesSivTest::SIV_KEYS[32] = {
    // Part 1: fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    // Part 2: f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

unsigned char AesSivTest::PLAIN_TEXT[16] = {
    // 11223344 55667788 99aabbcc ddee
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00, 0x00
};

unsigned char AesSivTest::AD_H1[24] = {
    //AD  (H1)  10111213 14151617 18191a1b 1c1d1e1f
    //          20212223 24252627
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};

CPPUNIT_TEST_SUITE_REGISTRATION( AesSivTest );
