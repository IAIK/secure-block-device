/*
 * SbdiTest.h
 *
 *  Created on: May 23, 2014
 *      Author: dhein
 */

#ifndef SBDITEST_H_
#define SBDITEST_H_

#include <cstddef>

static int memchrcmp(unsigned char *buffer, int chr, size_t len)
{
  for (size_t i = 0; i < len; ++i) {
    if (buffer[i] != (unsigned char) chr) {
      return 0;
    }
  }
  return 1;
}

#endif /* SBDITEST_H_ */
