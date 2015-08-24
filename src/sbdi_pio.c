/*
 * sbdi_pio.c
 *
 *  Created on: May 30, 2014
 *      Author: dhein
 */

#include "sbdi_pio.h"

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

//----------------------------------------------------------------------
static ssize_t bl_pread_i(void *iod, void *buf, size_t nbyte, off_t offset)
{
  int fd = *((int *)iod);
  return pread(fd, buf, nbyte, offset);
}

//----------------------------------------------------------------------
static ssize_t bl_pwrite_i(void *iod, const void * buf, size_t nbyte, off_t offset)
{
  int fd = *((int *)iod);
  return pwrite(fd, buf, nbyte, offset);
}

//----------------------------------------------------------------------
static ssize_t bl_generate_seed_i(uint8_t *buf, size_t nbyte)
{
  int rfh = open("/dev/random", O_RDONLY);
  if (rfh < 0) {
    return -1;
  }
  size_t l = 0;
  while (l < nbyte) {
    ssize_t r = read(rfh, buf + l, nbyte - l);
    if (r < 0) {
      close(rfh);
      return -1;
    }
    l += r;
  }
  close(rfh);
  return l;
}

//----------------------------------------------------------------------
sbdi_pio_t *sbdi_pio_create(void *iod, off_t size_at_open)
{
  sbdi_pio_t *io = calloc(1, sizeof(sbdi_pio_t));
  if (!io) {
    return NULL;
  }
  io->iod = iod;
  io->pread = &bl_pread_i;
  io->pwrite = &bl_pwrite_i;
  io->genseed = &bl_generate_seed_i;
  return io;
}

//----------------------------------------------------------------------
void sbdi_pio_delete(sbdi_pio_t *io) {
  free(io);
}

