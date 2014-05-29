/*
 * sbdi_file_backend.c
 *
 *  Created on: May 13, 2014
 *      Author: dhein
 */

#include "secblock.h"
#include "siv.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

//----------------------------------------------------------------------
sbdi_error_t sdbi_fb_open(int *fd)
{
  if (fd == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  *fd = open("sbdi_fb.raw", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (*fd == -1) {
    return SBDI_ERR_IO;
  }
  return SBDI_SUCCESS;
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_close(int fd)
{
  int r = close(fd);
  if (r == -1) {
    return SBDI_ERR_IO;
  }
  return SBDI_SUCCESS;
}
