/*
 * AesSivTest.cpp
 *
 *  Created on: May 14, 2014
 *      Author: dhein
 */

#include "crypto/siv.h"

#include <string>
#include <string.h>

#include <cppunit/extensions/HelperMacros.h>

#define PT_LEN 14
#define IV_LEN 16
#define AD_LEN 24

class AesSivTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE( AesSivTest );
  CPPUNIT_TEST( testSivEncryption );
  CPPUNIT_TEST( testSivDecryption );
  CPPUNIT_TEST_SUITE_END();

private:
  static unsigned char SIV_KEYS[32];
  static unsigned char PLAIN_TEXT[PT_LEN];
  static unsigned char AD_H1[AD_LEN];

  static unsigned char TV_CIPHER_TEXT[PT_LEN];
  static unsigned char TV_IV[IV_LEN];

  siv_ctx ctx;
  unsigned char CIPHER_TEXT[PT_LEN];
  unsigned char IV[IV_LEN];

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
    siv_encrypt(&ctx, PLAIN_TEXT, CIPHER_TEXT, PT_LEN, IV, 1, AD_H1, AD_LEN);
    CPPUNIT_ASSERT(!memcmp(CIPHER_TEXT, TV_CIPHER_TEXT, PT_LEN));
    CPPUNIT_ASSERT(!memcmp(IV, TV_IV, IV_LEN));
  }

  void testSivDecryption()
  {
    unsigned char DECRYPTED_PT[PT_LEN];
    siv_encrypt(&ctx, PLAIN_TEXT, CIPHER_TEXT, PT_LEN, IV, 1, AD_H1, AD_LEN);
    siv_decrypt(&ctx, CIPHER_TEXT, DECRYPTED_PT, PT_LEN, IV, 1, AD_H1, AD_LEN);
    CPPUNIT_ASSERT(!memcmp(PLAIN_TEXT, DECRYPTED_PT, PT_LEN));
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

unsigned char AesSivTest::PLAIN_TEXT[PT_LEN] = {
  // 11223344 55667788 99aabbcc ddee
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
};

unsigned char AesSivTest::AD_H1[24] = {
  //AD  (H1)  10111213 14151617 18191a1b 1c1d1e1f
  //          20212223 24252627
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};

unsigned char AesSivTest::TV_CIPHER_TEXT[14] = {
  // 40c02b96 90c4dc04 daef7f6a fe5c
  0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
  0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c
};
unsigned char AesSivTest::TV_IV[16] = {
  // 85632d07 c6e8f37f 950acd32 0a2ecc93
  0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
  0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93
};

CPPUNIT_TEST_SUITE_REGISTRATION( AesSivTest );
