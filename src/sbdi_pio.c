/*
 * sbdi_pio.c
 *
 *  Created on: May 30, 2014
 *      Author: dhein
 */

#include "sbdi_pio.h"

#include <unistd.h>
#include <stdlib.h>

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
sbdi_pio_t *sbdi_pio_create(void *iod, off_t size_at_open)
{
  sbdi_pio_t *io = calloc(1, sizeof(sbdi_pio_t));
  if (!io) {
    return NULL;
  }
  io->iod = iod;
  io->pread = &bl_pread_i;
  io->pwrite = &bl_pwrite_i;
  return io;
}

//----------------------------------------------------------------------
void sbdi_pio_delete(sbdi_pio_t *io) {
  free(io);
}

