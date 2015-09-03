///
/// \file
/// \brief Memory buffer for reading and writing primitive data types to an
/// untyped memory region (interface).
///

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_BUFFER_H_
#define SBDI_BUFFER_H_

#include <stdint.h>
#include <stdlib.h>

#include "sbdi_ctr_128b.h"

/*!
 * \brief defines data type for reading and writing data to and from a byte
 * buffer
 */
typedef struct sbdi_buffer {
  uint8_t *buffer; //!< the actual byte data buffer
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
 * \brief Returns a pointer to the data buffer underlying the SBDI buffer
 * that points to the current offset of the SBDI buffer
 *
 * Basically, this function provides unsafe access to the underlying data
 * buffer. The caller must ensure that the position is updated, if necessary.
 *
 * @param buf[in] a pointer to the buffer from which to extract the pointer
 * @return a pointer to the underlying data buffer at the current SBDI buffer
 * offset
 */
uint8_t *sbdi_buffer_get_cptr(const sbdi_buffer_t *buf);

/*!
 * \brief Returns a pointer to the data buffer underlying the SBDI buffer
 * that points to the specified byte offset
 *
 * Basically, this function provides unsafe access to the underlying data
 * buffer. The caller must ensure that the position is updated, if necessary.
 * The function ensures that the given offset is less then the length of the
 * buffer.
 *
 * @param buf[in] a pointer to the buffer from which to extract the pointer
 * @param off[in] the byte offset into the buffer (must be less than the
 * length of the buffer)
 * @return a pointer to the underlying data buffer at the specified offset
 */
uint8_t *sbdi_buffer_get_cptr_off(const sbdi_buffer_t *buf, const uint32_t off);

/*!
 * \brief Add a value to the position pointer (offset) of the SBDI buffer
 *
 * @param buf[inout] a pointer to the buffer to update
 * @param add[in] the value to add to the position
 */
void sbdi_buffer_add_pos(sbdi_buffer_t *buf, const uint32_t add);

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
 * \brief Writes the given unsigned 64 bit integer into the buffer
 *
 * @param buf[inout] a pointer to the buffer to which to write
 * @param value[in] the value to write
 */
void sbdi_buffer_write_uint64_t(sbdi_buffer_t *buf, const uint64_t value);

/*!
 * \brief Writes length bytes from src into the buffer
 *
 * @param buf[inout] a pointer to the buffer to write to
 * @param src[in] a pointer to the data buffer to read from
 * @param length[in] the number of bytes to copy from src into the buffer
 */
void sbdi_buffer_write_bytes(sbdi_buffer_t *buf, const uint8_t *src,
    const size_t length);

/*!
 * \brief Writes the given 128 bit counter into the buffer
 *
 * @param buf[inout] a pointer to the buffer to write to
 * @param ctr[in] a pointer to the 128 bit counter to write into the buffer
 */
void sbdi_buffer_write_ctr_128b(sbdi_buffer_t *buf, const sbdi_ctr_128b_t *ctr);

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

/*!
 * \brief Reads a unsigned 64 bit integer from the buffer
 *
 * @param buf[inout] a pointer to the buffer from which to read
 * @return the unsigned 64 bit integer read from the buffer
 */
uint64_t sbdi_buffer_read_uint64_t(sbdi_buffer_t *buf);

/*!
 * \brief Reads length bytes from the buffer and writes them into dest
 *
 * @param buf[inout] a pointer to the buffer to read from
 * @param dest[inout] a pointer to the byte buffer to write to
 * @param length[in] the number of bytes to copy from the buffer to dest
 */
void sbdi_buffer_read_bytes(sbdi_buffer_t *buf, uint8_t *dest,
    const size_t length);

/*!
 * \brief Reads a 128b counter from the buffer
 *
 * @param buf[inout] a pointer to the buffer to read from
 * @param ctr[out] a pointer to the 128 bit counter to read from the buffer
 * @returns SBDI_SUCCESS if the counter could be initialized;
 *          SBDI_ILLEGAL_PARAM otherwise
 */
sbdi_error_t sbdi_buffer_read_ctr_128b(sbdi_buffer_t *buf, sbdi_ctr_128b_t *ctr);

#endif /* SBDI_BUFFER_H_ */

#ifdef __cplusplus
}
#endif
