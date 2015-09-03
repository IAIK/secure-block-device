/* Copyright (c) IAIK, Graz University of Technology, 2015.
 * All rights reserved.
 * Contact: http://opensource.iaik.tugraz.at
 * 
 * This file is part of the Secure Block Device Library.
 * 
 * Commercial License Usage
 * Licensees holding valid commercial licenses may use this file in
 * accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and SIC. For further information
 * contact us at http://opensource.iaik.tugraz.at.
 * 
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License as published by the Free Software Foundation version 2.
 * 
 * The Secure Block Device Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with the Secure Block Device Library. If not, see <http://www.gnu.org/licenses/>.
 */
///
/// \file
/// \brief Tests the SIV implementaion used by the Secure Block Device Library.
///
#include "crypto/siv.h"

#include <string>
#include <string.h>

#include <cppunit/extensions/HelperMacros.h>

#define PT_LEN 14
#define PT2_LEN 16
#define IV_LEN 16
#define AD_LEN 24

class AesSivTest: public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE( AesSivTest );
  CPPUNIT_TEST(testSivEncryption);
  CPPUNIT_TEST(testSivDecryption);
  CPPUNIT_TEST(testSivInplaceEnDecryption);
  CPPUNIT_TEST(testSivAesCmac);
  CPPUNIT_TEST_SUITE_END();

private:
  static unsigned char SIV_KEYS[32];
  static unsigned char PLAIN_TEXT[PT_LEN];
  static unsigned char PLAIN_TEXT_2[IV_LEN];
  static unsigned char PLAIN_TEXT_3[IV_LEN*2];
  static unsigned char AD_H1[AD_LEN];

  static unsigned char TV_CIPHER_TEXT[PT_LEN];
  static unsigned char TV_IV[IV_LEN];

  siv_ctx ctx;
  siv_ctx tst;
  unsigned char CIPHER_TEXT[PT_LEN];
  unsigned char IV[IV_LEN];

  unsigned char tst_mem[PT2_LEN * 10];
  unsigned char iv_mem[IV_LEN * 10];

public:
  void setUp()
  {
    siv_init(&ctx, SIV_KEYS, SIV_256);
    siv_init(&tst, SIV_KEYS, SIV_256);
    memset(tst_mem, 0, PT2_LEN * 10);
    memset(iv_mem, 0, IV_LEN * 10);
  }

  void tearDown()
  {
    siv_restart(&ctx);
    siv_restart(&tst);
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

  inline unsigned char *tstMemIdx(unsigned idx)
  {
    return tst_mem + idx * PT2_LEN;
  }

  inline unsigned char *ivMemIdx(unsigned idx)
  {
    return iv_mem + idx * IV_LEN;
  }

  inline void enc(const unsigned char *pt, unsigned char *ct, unsigned char *iv,
      int len)
  {
    CPPUNIT_ASSERT(siv_encrypt(&ctx, pt, ct, len, iv, 1, AD_H1, AD_LEN) != -1);
  }

  inline void enc2(const unsigned char *pt, unsigned char *ct,
      unsigned char *iv, int len)
  {
    CPPUNIT_ASSERT(siv_encrypt(&tst, pt, ct, len, iv, 1, AD_H1, AD_LEN) != -1);
  }

  inline void dec(const unsigned char *ct, unsigned char *pt, unsigned char *iv,
      int len)
  {
    CPPUNIT_ASSERT(siv_decrypt(&ctx, ct, pt, len, iv, 1, AD_H1, AD_LEN) != -1);
  }

  inline void dec2(const unsigned char *ct, unsigned char *pt,
      unsigned char *iv, int len)
  {
    CPPUNIT_ASSERT(siv_decrypt(&tst, ct, pt, len, iv, 1, AD_H1, AD_LEN) != -1);
  }

  void testSivInplaceEnDecryption()
  {
    enc(PLAIN_TEXT_2, tstMemIdx(0), ivMemIdx(0), PT2_LEN);
    enc(tstMemIdx(0), tstMemIdx(1), ivMemIdx(1), PT2_LEN);
    enc(PLAIN_TEXT_2, tstMemIdx(2), ivMemIdx(2), PT2_LEN);
    enc(tstMemIdx(2), tstMemIdx(2), ivMemIdx(9), PT2_LEN);
    CPPUNIT_ASSERT(!memcmp(tstMemIdx(1), tstMemIdx(2), PT2_LEN));
    dec(tstMemIdx(1), tstMemIdx(3), ivMemIdx(1), PT2_LEN);
    CPPUNIT_ASSERT(!memcmp(tstMemIdx(0), tstMemIdx(3), PT2_LEN));
    dec(tstMemIdx(3), tstMemIdx(4), ivMemIdx(0), PT2_LEN);
    CPPUNIT_ASSERT(!memcmp(PLAIN_TEXT_2, tstMemIdx(4), PT2_LEN));
    dec(tstMemIdx(2), tstMemIdx(2), ivMemIdx(9), PT2_LEN);
    dec(tstMemIdx(2), tstMemIdx(2), ivMemIdx(2), PT2_LEN);
    CPPUNIT_ASSERT(!memcmp(PLAIN_TEXT_2, tstMemIdx(2), PT2_LEN));
  }

  void testSivCtxSwitches()
  {
    enc(PLAIN_TEXT_2, tstMemIdx(0), ivMemIdx(0), PT2_LEN);
    enc2(tstMemIdx(0), tstMemIdx(1), ivMemIdx(1), PT2_LEN);
    dec(tstMemIdx(1), tstMemIdx(3), ivMemIdx(1), PT2_LEN);
    dec2(tstMemIdx(3), tstMemIdx(4), ivMemIdx(0), PT2_LEN);
  }

  void testSivAesCmac() {
    memcpy(iv_mem, PLAIN_TEXT_2, PT2_LEN);
    memcpy(iv_mem + PT2_LEN, PLAIN_TEXT_3, IV_LEN*2);
    sbdi_bl_aes_cmac(&ctx, PLAIN_TEXT_2, PT2_LEN, PLAIN_TEXT_3, IV_LEN*2, tstMemIdx(0));
    aes_cmac(&tst, iv_mem, (IV_LEN * 3), tstMemIdx(1));
    CPPUNIT_ASSERT(!memcmp(tstMemIdx(0), tstMemIdx(1), PT2_LEN));
    CPPUNIT_ASSERT(memcmp(tstMemIdx(0), tstMemIdx(2), PT2_LEN));
  }

};

unsigned char AesSivTest::SIV_KEYS[32] = {
    // Part 1: fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
    0xf3, 0xf2, 0xf1, 0xf0,
    // Part 2: f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff };

unsigned char AesSivTest::PLAIN_TEXT[PT_LEN] = {
    // 11223344 55667788 99aabbcc ddee
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee };

unsigned char AesSivTest::PLAIN_TEXT_2[IV_LEN] = { 0x00, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

unsigned char AesSivTest::PLAIN_TEXT_3[IV_LEN*2] = {
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

unsigned char AesSivTest::AD_H1[24] = {
    //AD  (H1)  10111213 14151617 18191a1b 1c1d1e1f
    //          20212223 24252627
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };

unsigned char AesSivTest::TV_CIPHER_TEXT[14] = {
    // 40c02b96 90c4dc04 daef7f6a fe5c
    0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04, 0xda, 0xef, 0x7f, 0x6a,
    0xfe, 0x5c };
unsigned char AesSivTest::TV_IV[16] = {
    // 85632d07 c6e8f37f 950acd32 0a2ecc93
    0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f, 0x95, 0x0a, 0xcd, 0x32,
    0x0a, 0x2e, 0xcc, 0x93 };

CPPUNIT_TEST_SUITE_REGISTRATION(AesSivTest);
