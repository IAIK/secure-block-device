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
/// \brief An implementation of the Secure Block Device Libarary's block
/// device abstraction layer that uses files as storage back end.
///

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

