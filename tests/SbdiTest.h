/*
 * SbdiTest.h
 *
 *  Created on: May 23, 2014
 *      Author: dhein
 */

#ifndef SBDITEST_H_
#define SBDITEST_H_

#include <cassert>
#include <cstddef>
#include <cstdint>

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

#endif /* SBDITEST_H_ */
