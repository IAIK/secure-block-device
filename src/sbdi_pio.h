/*
 * sbdi_pio.h
 *
 *  Created on: May 30, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_PIO_H_
#define SBDI_PIO_H_

#include <sys/types.h>

/*!
 * \brief Defines a function pointer very similar to pread
 *
 * @param iod[in] a pointer to the I/O descriptor, e.g. a pointer to a file
 *                descriptor
 * @param buf[out] a pointer to the output buffer
 * @param nbyte[in] the number of bytes to read
 * @param offset[in] the offset of the data to read
 * @return the number of bytes read if successful; -1 otherwise
 */
typedef ssize_t (bl_pread)(void *iod, void *buf, size_t nbyte, off_t offset);

/*!
 * \brief Defines a pwrite like function pointer
 *
 * @param iod[in] a pointer to the I/O descriptor, e.g. a pointer to a file
 *                descriptor
 * @param buf[in] a pointer to a buffer containing the data to write
 * @param nbyte[in] the number of bytes to write
 * @param offset the offset where to write the data
 * @return the number of bytes written if successful; -1 otherwise
 */
typedef ssize_t (bl_pwrite)(void *iod, const void * buf, size_t nbyte,
    off_t offset);

/*!
 * \brief wrapper data type to hide pread and pwrite implementation
 */
typedef struct sbdi_pio {
  void *iod;          //!< I/O descriptor pointer, e.g. file decriptor pointer
  off_t size_at_open; //!< the size of the block device store at time of opening
  bl_pread *pread;    //!< pread like function pointer
  bl_pwrite *pwrite;  //!< pwrite like function pointer
} sbdi_pio_t;

/*!
 * \brief creates a new pio type using pread and pwrite as underlying
 * implementation
 *
 * This function follows the callee allocates callee frees pattern. Use
 * sbdi_pio_delete to free the memory allocated for the pio type.
 *
 * @param iod[in] a void pointer to the file descriptor used for the
 * underlying pread and pwrite
 * @return a pointer to a pio type if successful; NULL otherwise
 */
sbdi_pio_t *sbdi_pio_create(void *iod, off_t size_at_open);

/*!
 * \brief frees the memory allocated for the given pio type
 *
 * @param pio[in] a pointer to the pio type to delete
 */
void sbdi_pio_delete(sbdi_pio_t *pio);

#endif /* SBDI_PIO_H_ */

#ifdef __cplusplus
}
#endif
