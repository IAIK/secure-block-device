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
/// \brief Normal World Crypto Performance Test
///
#ifndef NWD_STOPWATCH_H
#define NWD_STOPWATCH_H

#include <stdint.h>
#include <time.h>

// Performance measurement time-span
typedef struct nwd_stopwatch {
  struct timespec start; // Start of measurement
  struct timespec stop;  // End of measurement
} nwd_stopwatch_t;

void nwd_stopwatch_init(void);
void nwd_stopwatch_start(nwd_stopwatch_t *sw) __attribute__((noinline));
void nwd_stopwatch_stop(nwd_stopwatch_t *sw) __attribute__((noinline));
int64_t nwd_stopwatch_nanos(const struct timespec *ts);
int64_t nwd_stopwatch_delta(const nwd_stopwatch_t *sw);
int64_t nwd_stopwatch_measure(void (*func)(void*), void *arg, size_t iterations) __attribute__((noinline));

#endif // NWD_STOPWATCH_H
