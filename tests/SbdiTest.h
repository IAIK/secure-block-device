/*
 * SbdiTest.h
 *
 *  Created on: May 23, 2014
 *      Author: dhein
 */

#ifndef SBDITEST_H_
#define SBDITEST_H_

#include "sbdi_err.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

#define FILE_NAME "sbdi_tst_enc"

#define ASS_SUC(f) CPPUNIT_ASSERT((f) == SBDI_SUCCESS)
#define ASS_ERR_ILL_PAR(f) CPPUNIT_ASSERT((f) == SBDI_ERR_ILLEGAL_PARAM)

/*!
 * \brief Checks if every byte in the given buffer is set to the specified
 * value
 * @param buffer[in] the unsigned byte buffer to check the contents of
 * @param chr[in] the byte to compare each byte in the buffer to
 * @param len[in] the length of the buffer in bytes
 * @return 1 if each byte in the buffer equals the specified value; 0
 * otherwise
 */
static int memchrcmp(const unsigned char *buffer, const int chr,
    const size_t len)
{
  assert(chr <= UINT8_MAX);
  for (size_t i = 0; i < len; ++i) {
    if (buffer[i] != (unsigned char) chr) {
      return 0;
    }
  }
  return 1;
}

/*!
 * \brief convert an SBDI error code to a human readable description
 *
 * @param r[in] the error code to convert
 * @return a human readable representation of the error code
 */
static const char *err_to_string(sbdi_error_t r)
{
  {
    switch (r) {
    case SBDI_SUCCESS:
      return "success";
    case SBDI_ERR_OUT_Of_MEMORY:
      return "out of memory";
    case SBDI_ERR_ILLEGAL_PARAM:
      return "illegal parameter";
    case SBDI_ERR_ILLEGAL_STATE:
      return "illegal state";
    case SBDI_ERR_IO:
      return "IO error";
    case SBDI_ERR_IO_MISSING_BLOCK:
          return "missing block";
    case SBDI_ERR_IO_MISSING_DATA:
      return "missing data";
    case SBDI_ERR_UNSUPPORTED:
      return "operation unsupported";
    case SBDI_ERR_TAG_MISMATCH:
      return "tag mismatch";
    case SBDI_ERR_CRYPTO_FAIL:
      return "crypto fail";
    case SBDI_ERR_UNSPECIFIED:
      return "unspecified";
    default:
      return "unknown error";
    }
  }
}

#endif /* SBDITEST_H_ */
