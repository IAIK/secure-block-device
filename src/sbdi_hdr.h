/*
 * sbdi_hdr.h
 *
 *  Created on: May 30, 2014
 *      Author: dhein
 */

#ifndef SBDI_HDR_H_
#define SBDI_HDR_H_

void sbdi_derive_hdr_v1_key(siv_ctx *master, sbdi_hdr_v1_sym_key_t key,
    uint8_t *n1, size_t n1_len, uint8_t *n2, size_t n2_len);

sbdi_error_t sbdi_create_hdr_v1(sbdi_hdr_v1_t **hdr, sbdi_hdr_v1_sym_key_t key);
void sbdi_delete_hdr_v1(sbdi_hdr_v1_t *hdr);

sbdi_error_t sbdi_read_hdr_v1(sbdi_t *sbdi, sbdi_hdr_v1_t **hdr,
    siv_ctx *master);

sbdi_error_t sbdi_write_hdr_v1(sbdi_t *sbdi, const sbdi_hdr_v1_t *hdr,
    siv_ctx *master);

#endif /* SBDI_HDR_H_ */
