// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef AZIOT_TPM_H
#define AZIOT_TPM_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdlib>
extern "C" {
#else
#include <stddef.h>
#include <stdlib.h>
#endif /* __cplusplus */

/** @file */

/**
 * @brief   One-time init function for the azoit-tpm library
 *
 * @return  On success 0 on. Non-zero on failure
 */
int aziot_tpm_init();

typedef void* AZIOT_TPM_HANDLE;

/**
 * @brief   Creates a client for the associated interface
 *
 * @return  An instance handle that is passed into most functions of the interface.
 */
AZIOT_TPM_HANDLE aziot_tpm_create();

/**
 * @brief   Releases a client instance created with `aziot_tpm_create`
 */
void aziot_tpm_destroy(AZIOT_TPM_HANDLE handle);

/**
* @brief    Frees buffers allocated by the HSM library.
*           Used to ensure that the buffers allocated in one CRT are freed in the same
*           CRT. Intended to be used for TPM keys.
*
* @param buffer     A buffer allocated and owned by HSM library.
*
*/
void aziot_tpm_free_buffer(void* buffer);

/**
* @brief            Imports a key that has been previously encrypted with the endorsement
*                   key and storage root key into the TPM key storage
*
* @param handle     The ::AZIOT_TPM_HANDLE that was created by the `aziot_tpm_create` call
* @param key        The key that needs to be imported to the TPM
* @param key_size   The size of the key
*
* @return           On success 0 on. Non-zero on failure
*/
int aziot_tpm_import_auth_key(
    AZIOT_TPM_HANDLE handle,
    const unsigned char* key, size_t key_len
);

/**
* @brief                Retrieves the endorsement and storage root keys of the TPM
*
* @param handle         The ::AZIOT_TPM_HANDLE that was created by the `aziot_tpm_create` call
* @param[out] ek        The returned endorsement key. This function allocates memory for a buffer
*                       which must be freed by a call to `aziot_tpm_free_buffer`.
* @param[out] ek_size   The size of the returned key
* @param[out] srk       The returned storage root key. This function allocates memory for a buffer
*                       which must be freed by a call to `aziot_tpm_free_buffer`.
* @param[out] srk_size  The size of the returned key
*
* @return               On success 0 on. Non-zero on failure
*/
int aziot_tpm_get_keys(
    AZIOT_TPM_HANDLE handle,
    unsigned char** ek, size_t* ek_size,
    unsigned char** srk, size_t* srk_size
);

/**
* @brief                    Hashes the data with the key stored in the TPM
*
* @param handle             ::AZIOT_TPM_HANDLE that was created by the `aziot_tpm_create` call
* @param data               Data that will need to be hashed
* @param data_size          The size of the data parameter
* @param[out] digest        The returned digest. This function allocates memory for a buffer
*                           which must be freed by a call to `aziot_tpm_free_buffer`.
* @param[out] digest_size   The size of the returned digest
*
* @return                   On success 0 on. Non-zero on failure
*/
int aziot_tpm_sign_with_auth_key(
    AZIOT_TPM_HANDLE handle,
    const unsigned char* data, size_t data_size,
    unsigned char** digest, size_t* digest_size
);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // AZIOT_TPM_H
