///
/// \file
/// \brief Normal World Crypto Performance Test
///
#define _GNU_SOURCE 1
#include "nwd-stopwatch.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <math.h>

// The clock (time-base) to be used for performance measurements
//
// Typical sensible values are [cf. time(8)]:
//  CLOCK_REALTIME           - System-wide  clock  that measures real (i.e., wall-clock)
//                             time.
//  CLOCK_MONOTONIC          - Clock  that  cannot  be set and represents monotonic time
//  CLOCK_MONOTONIC_RAW        since some unspecified starting point.
//
//  CLOCK_PROCESS_CPUTIME_ID - High-resolution per-process timer from the CPU.
//
static clockid_t g_clock_id = CLOCK_MONOTONIC_RAW;

// Clock resolution (in ns)
static int64_t g_clock_res = UINT64_C(1);

// Estimated syscall overhead (average)
static double g_clock_overhead_avg = 0.0;

// Estimated deviation of syscall overhead (sigma)
static double g_clock_overhead_dev = 0.0;

//----------------------------------------------------------------------
static __attribute__((noinline)) void nwd_stopwatch_dummy(void *unused)
{
  __asm__ volatile ("nop" : : : "memory");
}

//----------------------------------------------------------------------
void nwd_stopwatch_init(void)
{
  // Determine the clock resolution
  struct timespec ts;
  if (clock_getres(g_clock_id, &ts) != 0) {
    perror("stopwatch: failed to determine clock resolution.");
    abort();
  }

  g_clock_res = nwd_stopwatch_nanos(&ts);
  if (g_clock_res <= 0) {
    fprintf(stderr, "stopwatch: broken clock_getres() result. assuming 1ns\n");
    g_clock_res = 1;
  }

  // Estimate the overhead of an nwd_stopwatch_measure() call with an empty target function.
  const size_t count = 100000;
  int64_t total = 0;
  double square_sum = 0.0;

  for (size_t n = 0; n < count; ++n) {
    int64_t sample = nwd_stopwatch_measure(&nwd_stopwatch_dummy, NULL, 1);
    total += sample;
    square_sum += (double) sample * (double) sample;
  }

  g_clock_overhead_avg = (double) total / (double) count;
  g_clock_overhead_dev = sqrt((square_sum - (double) total * (double) total / count) / (count - 1.0));

  // Print setup
  printf("stopwatch resolution: %" PRId64 "\n", g_clock_res);
  printf("stopwatch overhead(avg) %g\n", g_clock_overhead_avg);
  printf("stopwatch overhead(dev) %g\n", g_clock_overhead_dev);
}

//----------------------------------------------------------------------
void nwd_stopwatch_start(nwd_stopwatch_t *sw)
{
  memset(sw, 0, sizeof(nwd_stopwatch_t));

  if (clock_gettime(g_clock_id, &sw->start) != 0) {
    perror("stopwatch: failed to measure start time");
    abort();
  }
}

//----------------------------------------------------------------------
void nwd_stopwatch_stop(nwd_stopwatch_t *sw)
{
  if (clock_gettime(g_clock_id, &sw->stop) != 0) {
    perror("stopwatch: failed to measure stop time");
    abort();
  }
}

//----------------------------------------------------------------------
int64_t nwd_stopwatch_nanos(const struct timespec *ts)
{
  return ts->tv_sec * INT64_C(1000000000) + ts->tv_nsec;
}

//----------------------------------------------------------------------
int64_t nwd_stopwatch_delta(const nwd_stopwatch_t *sw)
{
  int64_t t_start = nwd_stopwatch_nanos(&sw->start);
  int64_t t_stop = nwd_stopwatch_nanos(&sw->stop);

  // Clamp to INT64_MAX on wrap-around
  if (t_start > t_stop) {
    return INT64_MAX;
  }

  return t_stop - t_start;
}

//----------------------------------------------------------------------
int64_t nwd_stopwatch_measure(void (*func)(void*), void *arg, size_t iterations)
{
  nwd_stopwatch_t sw;
  assert (func != NULL);

  // Measure n rounds
  nwd_stopwatch_start(&sw);
  for (size_t n = 0; n < iterations; ++n) {
    func(arg);
  }
  nwd_stopwatch_stop(&sw);

  return nwd_stopwatch_delta(&sw) / iterations;
}
