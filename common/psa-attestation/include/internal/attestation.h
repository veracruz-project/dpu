/*
 * Copyright (c) 2018-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __ATTESTATION_H__
#define __ATTESTATION_H__

#include "psa/initial_attestation.h"
//#include "tfm_client.h"
//#include "bl2/include/tfm_boot_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief Type of memory access
 */
enum attest_memory_access_t {
    TFM_ATTEST_ACCESS_RO = 1,
    TFM_ATTEST_ACCESS_RW = 2,
};

/**
 * \enum psa_attest_err_t
 *
 * \brief Initial attestation service error types
 *
 */
enum psa_attest_err_t {
    /** Action was performed successfully */
    PSA_ATTEST_ERR_SUCCESS = 0,
    /** Boot status data is unavailable or malformed */
    PSA_ATTEST_ERR_INIT_FAILED,
    /** Buffer is too small to store required data */
    PSA_ATTEST_ERR_BUFFER_OVERFLOW,
    /** Some of the mandatory claims are unavailable*/
    PSA_ATTEST_ERR_CLAIM_UNAVAILABLE,
    /** Some parameter or combination of parameters are recognised as invalid:
     * - challenge size is not allowed
     * - challenge object is unavailable
     * - token buffer is unavailable
     */
    PSA_ATTEST_ERR_INVALID_INPUT,
    /** Unexpected error happened during operation */
    PSA_ATTEST_ERR_GENERAL,
    /** Following entry is only to ensure the error code of integer size */
    PSA_ATTEST_ERR_FORCE_INT_SIZE = INT_MAX
};

/*!
 * \brief Copy the boot data (coming from boot loader) from shared memory area
 *        to service memory area
 *
 * \param[in]   major_type  Major type of TLV entries to copy
 * \param[out]  ptr         Pointer to the buffer to store the boot data
 * \parma[in]   len         Size of the buffer to store the boot data
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
 #if 0
enum psa_attest_err_t
attest_get_boot_data(uint8_t major_type,
                     struct tfm_boot_data *boot_data,
                     uint32_t len);
#endif

/*!
 * \brief Get the ID of the caller thread.
 *
 * \param[out]  caller_id  Pointer where to store caller ID
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
 #if 1
enum psa_attest_err_t
attest_get_caller_client_id(int32_t *caller_id);
#endif

/*!
 * \brief Verify memory access rights
 *
 * \param[in]  addr    Pointer to the base of the address range to check
 * \param[in]  size    Size of the address range to check
 * \param[in]  access  Type of memory access as specified in
 *                     \ref attest_memory_access
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
 #if 0
enum psa_attest_err_t
attest_check_memory_access(void *addr,
                           uint32_t size,
                           enum attest_memory_access_t access);
#endif

/*!
 * \brief Initialise the initial attestation service during the TF-M boot up
 *        process.
 *
 * \return Returns PSA_SUCCESS if init has been completed,
 *         otherwise error as specified in \ref psa_status_t
 */
psa_status_t attest_init(void);

/*!
 * \brief Get initial attestation token
 *
 * \param[in]     in_vec     Pointer to in_vec array, which contains input data
 *                           to attestation service
 * \param[in]     num_invec  Number of elements in in_vec array
 * \param[in,out] out_vec    Pointer out_vec array, which contains output data
 *                           to attestation service
 * \param[in]     num_outvec Number of elements in out_vec array
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t
initial_attest_get_token(const uint8_t *fw_hash,
                         size_t         fw_hash_size,
                         const uint8_t *cert_hash,
                         size_t         cert_hash_size,
                         const char    *enclave_name,
                         size_t         enclave_name_size,
                         const uint8_t *auth_challenge,
                         size_t         challenge_size,
                         uint8_t       *token_buf,
                         size_t         token_buf_size,
                         size_t        *token_size);

/**
 * \brief Get the size of the initial attestation token
 *
 * \param[in]     in_vec     Pointer to in_vec array, which contains input data
 *                           to attestation service
 * \param[in]     num_invec  Number of elements in in_vec array
 * \param[out]    out_vec    Pointer to out_vec array, which contains pointer
 *                           where to store the output data
 * \param[in]     num_outvec Number of elements in out_vec array
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t
initial_attest_get_token_size(size_t fw_hash_size,
                              size_t cert_hash_size,
                              size_t enclave_name_size,
                              size_t  challenge_size,
                              size_t *token_size);

/**
 * \brief Get the initial attestation public key.
 *
 * \param[in]     in_vec     Pointer to in_vec array, which contains input data
 *                           to attestation service
 * \param[in]     num_invec  Number of elements in in_vec array
 * \param[out]    out_vec    Pointer to out_vec array, which contains pointer
 *                           where to store the output data
 * \param[in]     num_outvec Number of elements in out_vec array
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
 #if 0
psa_status_t
initial_attest_get_public_key(const psa_invec  *in_vec,  uint32_t num_invec,
                                    psa_outvec *out_vec, uint32_t num_outvec);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __ATTESTATION_H__ */
