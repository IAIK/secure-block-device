/*
 * sbdi_file_backend.c
 *
 *  Created on: May 13, 2014
 *      Author: dhein
 */

#include "secblock.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
sbdi_error_t sbdi_fb_read_hdr(const int fd, sbdi_hdr_t **hdr)
{
  if (fd == -1 || hdr == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  uint32_t version = 0;
  // Read version information
  ssize_t r = pread(fd, &version, sizeof(uint32_t), 0);
  if (r == -1) {
    return SBDI_ERR_IO;
  } else if (r < sizeof(uint32_t)) {
    return SBDI_ERR_MISSING_DATA;
  }
  if (version > SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (version == SBDI_HDR_VERSION_1) {
    sbdi_hdr_t *lhdr = calloc(1, sizeof(sbdi_hdr_t));
    if (!lhdr) {
      return SBDI_ERR_OUT_Of_MEMORY;
    }
    ssize_t r = pread(fd, lhdr, sizeof(sbdi_hdr_t), 0);
    if (r == -1) {
      free(lhdr);
      return SBDI_ERR_IO;
    } else if (r < sizeof(sbdi_hdr_t)) {
      // Empty/non-existent file, insufficient data
      free(lhdr);
      return SBDI_ERR_MISSING_DATA;
    }
    return SBDI_SUCCESS;
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_write_hdr(const int fd, const sbdi_hdr_t *hdr)
{
  if (fd == -1 || hdr == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (hdr->version < SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (hdr->version == SBDI_HDR_VERSION_1) {
    ssize_t r = pwrite(fd, hdr, sizeof(sbdi_hdr_t), 0);
    if (r == -1) {
      return SBDI_ERR_IO;
    } else if (r < sizeof(sbdi_hdr_t)) {
      return SBDI_ERR_MISSING_DATA;
    }
    return SBDI_SUCCESS;
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_read_key(const int fd, const sbdi_hdr_t *hdr,
    const uint32_t slot, uint8_t **key_blob)
{
  if (fd == -1 || hdr == NULL || slot > 7 || key_blob == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (hdr->version < SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (hdr->version == SBDI_HDR_VERSION_1) {
    size_t key_offset = 0;
    size_t blob_size = 0;
    if (slot == 0) {
      key_offset = 0x0100;
      blob_size = 0x10;
    } else {
      key_offset = 0x0200 * slot;
      blob_size = hdr->key_slots[slot].key_size;
    }
    uint8_t *kb = malloc(blob_size);
    if (!kb) {
      return SBDI_ERR_OUT_Of_MEMORY;
    }
    int r = pread(fd, kb, blob_size, key_offset);
    if (r == -1) {
      free(kb);
      return SBDI_ERR_IO;
    } else if (r < blob_size) {
      free(kb);
      return SBDI_ERR_MISSING_DATA;
    }
    *key_blob = kb;
    return SBDI_SUCCESS;
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
sbdi_error_t sbdi_fb_write_key(const int fd, sbdi_hdr_t *hdr,
    const uint32_t slot, uint8_t *key_blob)
{
  if (fd == -1 || hdr == NULL || slot > 7 || key_blob == NULL) {
    return SBDI_ERR_ILLEGAL_PARAM;
  }
  if (hdr->version < SBDI_HDR_SUPPORTED_VERSION) {
    return SBDI_ERR_UNSUPPORTED;
  }
  if (hdr->version == SBDI_HDR_VERSION_1) {
    size_t key_offset = 0;
    size_t blob_size = 0;
    if (slot == 0) {
      key_offset = 0x0100;
      blob_size = 0x10;
    } else {
      key_offset = 0x0200 * slot;
      blob_size = hdr->key_slots[slot].key_size;
    }
    int r = pwrite(fd, key_blob, blob_size, key_offset);
    if (r == -1) {
      return SBDI_ERR_IO;
    } else if (r < blob_size) {
      return SBDI_ERR_MISSING_DATA;
    }
    return SBDI_SUCCESS;
  } else {
    return SBDI_ERR_UNSUPPORTED;
  }
}

//----------------------------------------------------------------------
void sbdi_fb_free_hdr(sbdi_hdr_t *hdr)
{
  free(hdr);
}

//----------------------------------------------------------------------
void sbdi_fb_free_key_blob(uint8_t *key_blob)
{
  free(key_blob);
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
