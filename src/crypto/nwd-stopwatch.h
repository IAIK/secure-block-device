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
