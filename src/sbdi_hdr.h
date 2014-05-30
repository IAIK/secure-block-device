/*
 * sbdi_hdr.h
 *
 *  Created on: May 30, 2014
 *      Author: dhein
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SBDI_HDR_H_
#define SBDI_HDR_H_

#include "sbdi_config.h"
#include "sbdi_ctr_128b.h"
#include "sbdi_block.h"

#include "siv.h"

#include <stdint.h>

#define SBDI_HDR_VERSION_1 1u
#define SBDI_HDR_MAGIC_LEN 8u

#define SBDI_HDR_SUPPORTED_VERSION SBDI_HDR_VERSION_1

#define SBDI_HDR_V1_PACKED_SIZE 76u
#define SBDI_HDR_V1_KEY_SIZE    32u
#define SBDI_HDR_V1_TAG_SIZE    SBDI_BLOCK_TAG_SIZE

typedef uint8_t sbdi_hdr_magic_t[SBDI_HDR_MAGIC_LEN];
typedef uint8_t sbdi_hdr_v1_sym_key_t[SBDI_HDR_V1_KEY_SIZE];

static const sbdi_hdr_magic_t SBDI_HDR_MAGIC = {
    0xA1, 0x1D, 0x1F, 0xDE, 0xAD, 0xDA, 0x7A, 0xFF
};

/*!
 * \brief holds the information necessary to identify a secure block device
 * interface header and its version
 */
typedef struct secure_block_device_interface_header_id {
  sbdi_hdr_magic_t magic; //!< the magic number identifying a secure block device interface
  uint32_t version; //!< the version of the secure block device interface header
} sbdi_hdr_id_t;

/*!
 * \brief the secure block device interface header
 */
typedef struct secure_block_device_interface_header_v1 {
  sbdi_hdr_id_t id; //!< the secure block device interface identification information
  sbdi_ctr_128b_t ctr; //!< access counter protecting the header against replay attacks
  sbdi_hdr_v1_sym_key_t key; //!< the plaintext secure block device key
  sbdi_tag_t tag; //!< the tag protecting the integrity of the key
} sbdi_hdr_v1_t;


void sbdi_derive_hdr_v1_key(siv_ctx *master, sbdi_hdr_v1_sym_key_t key,
    uint8_t *n1, size_t n1_len, uint8_t *n2, size_t n2_len);

/*!
 * \brief creates a new secure block device v1 header
 *
 * This function follows a callee allocates, callee frees pattern. To release
 * the memory associated with the header and also clean up any key data left
 * in memory call the corresponding sbdi_delete_hdr_v1 function.
 *
 * @param hdr[out] an out pointer to the header set by this function on
 * successful header creation
 * @param key[in] the plaintext symmetric SBDI v1 key to store in this header
 * @return SBDI_SUCCESS if the header could be created successfully;
 *         SBDI_ERR_OUT_Of_MEMORY if the space for the header could not be
 *                                allocated;
 *         SBDI_ERR_ILLEGAL_PARAM if any of the given parameters is null.
 */
sbdi_error_t sbdi_create_hdr_v1(sbdi_hdr_v1_t **hdr, const sbdi_hdr_v1_sym_key_t key);

/*!
 * \brief Overwrites the key data and frees the memory allocated for the
 * secure block device v1 header
 *
 * @param hdr[in] the pointer to the header to delete
 */
void sbdi_delete_hdr_v1(sbdi_hdr_v1_t *hdr);

/*!
 * \brief tries to read a SBDI v1 header from from the secure block device
 *
 * This function follows a callee allocates, callee frees pattern. To release
 * the memory associated with the header and also clean up any key data left
 * in memory call the corresponding sbdi_delete_hdr_v1 function.
 *
 * This function tries to decrypt the SBDI specific key stored in the header.
 *
 * @param sbdi[in] a pointer to the secure block device interface to read the
 * header from
 * @param hdr[out] an out pointer to the header set by this function on
 * successful header creation
 * @param master[in] a pointer to the SIV context of the master key
 * @return SBDI_SUCCESS if the header could be read successfully;
 *         SBDI_ERR_ILLEGAL_PARAM if any of the given parameters is null, or
 *                                the Merkle tree is inconsistent;
 *         SBDI_ERR_OUT_Of_MEMORY if the space for the header could not be
 *                                allocated;
 *         SBDI_ERR_IO if there is an I/O error when reading from the SBDI;
 *         SBDI_ERR_IO_MISSING_BLOCK if there is no header block;
 *         SBDI_ERR_IO_MISSING_DATA if the header was incompletely written;
 *         SBDI_ERR_ILLEGAL_STATE if the written header magic does not match,
 *                                or if updating the Merkle tree fails;
 *         SBDI_ERR_UNSUPPORTED if the written version is higher than the
 *                              supported version;
 *         SBDI_ERR_TAG_MISMATCH if the key in the header has been modified.
 */
sbdi_error_t sbdi_read_hdr_v1(sbdi_t *sbdi, sbdi_hdr_v1_t **hdr,
    siv_ctx *master);

/*!
 * \brief Writes a secure block device interface header v1 to the SBDI
 *
 * This function encrypts the SBDI specific key before writing the header.
 *
 * @param sbdi[in] a pointer to the secure block device interface to write
 * the header to
 * @param hdr[in] a pointer to the header to write to the SBDI
 * @param master[in] a pointer to the SIV context of the master key
 * @return SBDI_SUCCESS if the header could be written successfully;
 *         SBDI_ERR_ILLEGAL_PARAM if any of the given parameters is null, or
 *                                the Merkle tree is inconsistent;
 *         SBDI_ERR_ILLEGAL_STATE if updating the Merkle tree fails;
 *         SBDI_ERR_IO if there is an I/O error when writing to the SBDI;
 *         SBDI_ERR_IO_MISSING_BLOCK if nothing could be written
 *         SBDI_ERR_IO_MISSING_DATA if the header was only partially written;
 *         SBDI_ERR_TAG_MISMATCH if the key in the header has been modified.
 */
sbdi_error_t sbdi_write_hdr_v1(sbdi_t *sbdi, const sbdi_hdr_v1_t *hdr,
    siv_ctx *master);

#endif /* SBDI_HDR_H_ */

#ifdef __cplusplus
}
#endif
