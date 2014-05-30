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
  SBDI_SUCCESS              =    0, /*!< Operation terminated successfully */
  SBDI_ERR_OUT_Of_MEMORY    =   -1, /*!< There was not enough memory to complete the operation */
  SBDI_ERR_ILLEGAL_PARAM    =   -2, /*!< At least one of the specified parameters was illegal */
  SBDI_ERR_ILLEGAL_STATE    =   -3, /*!< The operation reached an illegal state */
  SBDI_ERR_IO               =   -4, /*!< An I/O error occurred */
  SBDI_ERR_IO_MISSING_BLOCK =   -5, //!< Missing block
  SBDI_ERR_IO_MISSING_DATA  =   -6, /*!< Incomplete block */
  SBDI_ERR_UNSUPPORTED      =   -7, /*!< This operation or data format is not supported */
  SBDI_ERR_TAG_MISMATCH     =   -8, /*!< Cryptographic tag validation failed */
  SBDI_ERR_CRYPTO_FAIL      =   -9, /*!< The cryptographic layer fails to perform an operation such as an encryption */
  SBDI_ERR_UNSPECIFIED      = -255  /*!< A general error occurred */
} sbdi_error_t;

/*!
 * \brief wraps a given expression (e.g. a function call) with a test if the
 * result of the expression is MT_SUCCESS. If this is not the case, then the
 * macro returns the error code
 */
#define SBDI_ERR_CHK(f) do {sbdi_error_t r = (f);if (r != SBDI_SUCCESS) {return r;}} while (0)

/*!
 * \brief wraps a given expression and if the expression evaluates to false
 * returns SBDI_ERR_ILLEGAL_PARAM
 */
#define SBDI_CHK_PARAM(p) do {if (!(p)) {return SBDI_ERR_ILLEGAL_PARAM;}} while (0)

#endif /* SBDI_ERR_H_ */
