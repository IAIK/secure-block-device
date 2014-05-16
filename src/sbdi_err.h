/*
 * mt_err.h
 *
 *  Created on: 09.05.2014
 *      Author: dhein
 */

#ifndef SBDI_ERR_H_
#define SBDI_ERR_H_

/*!
 * \brief Used to convey error information, if a secure block device
 * interface operation fails.
 */
typedef enum sbdi_error {
  SBDI_SUCCESS           =    0, /*!< Operation terminated successfully */
  SBDI_ERR_OUT_Of_MEMORY =   -1, /*!< There was not enough memory to complete the operation */
  SBDI_ERR_ILLEGAL_PARAM =   -2, /*!< At least one of the specified parameters was illegal */
  SBDI_ERR_ILLEGAL_STATE =   -3, /*!< The operation reached an illegal state */
  SBDI_ERR_IO            =   -4, /*!< An I/O error occurred */
  SBDI_ERR_MISSING_DATA  =   -5, /*!< File not found */
  SBDI_ERR_UNSUPPORTED   =   -6, /*!< This operation or data format is not supported */
  SBDI_ERR_TAG_MISMATCH  =   -7, /*!< Cryptographic tag validation failed */
  SBDI_ERR_UNSPECIFIED   = -255  /*!< A general error occurred */
} sbdi_error_t;

#endif /* SBDI_ERR_H_ */
