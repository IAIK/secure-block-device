// Memory buffer for reading and writing primitive data types to a
// in untyped memory region.
//
// Copyright (C) 2014 IAIK, Graz University of Technology
// Author(s): Daniel Hein
//

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_BUFFER_H_
#define SBDI_BUFFER_H_

#include <stdint.h>
#include <stdlib.h>

/*!
 * \brief defines data type for reading and writing data to and from a byte
 * buffer
 */
typedef struct sbdi_buffer {
  unsigned char *buffer; //!< the actual byte data buffer
  size_t length;         //!< the total length of the buffer in bytes
  size_t pos; //!< the current position where the next read or write operation will be performed
} sbdi_buffer_t;

/*!
 * \brief initializes the given buffer with the given data buffer pointer and
 * buffer size
 *
 * @param buf[inout] a pointer to the buffer to initialize
 * @param buffer[in] the data buffer pointer to wrap with the SBDI buffer
 * @param length[in] the length in bytes of the data buffer
 */
void sbdi_buffer_init(sbdi_buffer_t *buf, uint8_t *buffer, const size_t length);

/*!
 * \brief Resets the buffer position to zero
 *
 * @param buf[inout] a pointer to the buffer to reset
 */
void sbdi_buffer_reset(sbdi_buffer_t *buf);

/*!
 * \brief Writes the given unsigned 8 bit integer into the buffer
 *
 * @param buf[inout] a pointer to the buffer to which to write
 * @param value[in] the value to write
 */
void sbdi_buffer_write_uint8_t(sbdi_buffer_t *buf, uint8_t value);

/*!
 * \brief Writes the given unsigned 16 bit integer into the buffer
 *
 * @param buf[inout] a pointer to the buffer to which to write
 * @param value[in] the value to write
 */
void sbdi_buffer_write_uint16_t(sbdi_buffer_t *buf, uint16_t value);

/*!
 * \brief Writes the given unsigned 32 bit integer into the buffer
 *
 * @param buf[inout] a pointer to the buffer to which to write
 * @param value[in] the value to write
 */
void sbdi_buffer_write_uint32_t(sbdi_buffer_t *buf, const uint32_t value);


/*!
 * \brief Reads a unsigned 8 bit integer from the buffer
 *
 * @param buf[inout] a pointer to the buffer from which to read
 * @return the unsigned 8 bit integer read from the buffer
 */
uint8_t sbdi_buffer_read_uint8_t(sbdi_buffer_t *buf);

/*!
 * \brief Reads a unsigned 16 bit integer from the buffer
 *
 * @param buf[inout] a pointer to the buffer from which to read
 * @return the unsigned 16 bit integer read from the buffer
 */
uint16_t sbdi_buffer_read_uint16_t(sbdi_buffer_t *buf);

/*!
 * \brief Reads a unsigned 32 bit integer from the buffer
 *
 * @param buf[inout] a pointer to the buffer from which to read
 * @return the unsigned 32 bit integer read from the buffer
 */
uint32_t sbdi_buffer_read_uint32_t(sbdi_buffer_t *buf);

#endif /* SBDI_BUFFER_H_ */

#ifdef __cplusplus
}
#endif
