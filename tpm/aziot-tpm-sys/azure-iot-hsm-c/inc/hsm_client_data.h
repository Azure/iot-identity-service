// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef HSM_CLIENT_DATA_H
#define HSM_CLIENT_DATA_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdlib>
extern "C" {
#else
#include <stddef.h>
#include <stdlib.h>
#endif /* __cplusplus */

/** @file */

int hsm_client_tpm_init();
void hsm_client_tpm_deinit();

typedef void* HSM_CLIENT_HANDLE;

/**
 * @brief   Creates a client for the associated interface
 *
 * @return  An instance handle that is passed into most functions of the interface.
 */
HSM_CLIENT_HANDLE hsm_client_tpm_create();
typedef HSM_CLIENT_HANDLE (*HSM_CLIENT_CREATE)();

/**
 * @brief   Releases a client instance created with ::HSM_CLIENT_CREATE
 */
void hsm_client_tpm_destroy(HSM_CLIENT_HANDLE handle);
typedef void (*HSM_CLIENT_DESTROY)(HSM_CLIENT_HANDLE handle);

/**
* @brief    Frees buffers allocated by the HSM library.
*           Used to ensure that the buffers allocated in one CRT are freed in the same
*           CRT. Intended to be used for TPM keys.
*
* @param buffer     A buffer allocated and owned by HSM library.
*
*/
void hsm_client_tpm_free_buffer(void* buffer);
typedef void (*HSM_CLIENT_FREE_BUFFER)(void* buffer);

// TPM
/**
* @brief            Imports a key that has been previously encrypted with the endorsement
*                   key and storage root key into the TPM key storage
*
* @param handle     The ::HSM_CLIENT_HANDLE that was created by the ::HSM_CLIENT_CREATE call
* @param key        The key that needs to be imported to the TPM
* @param key_size   The size of the key
*
* @return           On success 0 on. Non-zero on failure
*/
int hsm_client_tpm_activate_identity_key(
    HSM_CLIENT_HANDLE handle,
    const unsigned char* key, size_t key_len
);
typedef int (*HSM_CLIENT_ACTIVATE_IDENTITY_KEY)(HSM_CLIENT_HANDLE handle, const unsigned char* key, size_t key_size);

/**
* @brief                Retrieves the endorsement key of the TPM
*
* @param handle         The ::HSM_CLIENT_HANDLE that was created by the ::HSM_CLIENT_CREATE call
* @param[out] key       The returned endorsement key. This function allocates memory for a buffer
*                       which must be freed by a call to ::HSM_CLIENT_FREE_BUFFER.
* @param[out] key_size  The size of the returned key
*
* @return               On success 0 on. Non-zero on failure
*/
int hsm_client_tpm_get_endorsement_key(
    HSM_CLIENT_HANDLE handle,
    unsigned char** key, size_t* key_len
);
typedef int (*HSM_CLIENT_GET_ENDORSEMENT_KEY)(HSM_CLIENT_HANDLE handle, unsigned char** key, size_t* key_size);

/**
* @brief                Retrieves the storage root key of the TPM
*
* @param handle         The ::HSM_CLIENT_HANDLE that was created by the ::HSM_CLIENT_CREATE call
* @param[out] key       The returned storage root key. This function allocates memory for a buffer
*                       which must be freed by a call to ::HSM_CLIENT_FREE_BUFFER.
* @param[out] key_size  The size of the returned key
*
* @return               On success 0 on. Non-zero on failure
*/
int hsm_client_tpm_get_storage_key(
    HSM_CLIENT_HANDLE handle,
    unsigned char** key, size_t* key_len
);
typedef int (*HSM_CLIENT_GET_STORAGE_ROOT_KEY)(HSM_CLIENT_HANDLE handle, unsigned char** key, size_t* key_size);

/**
* @brief                    Hashes the data with the key stored in the TPM
*
* @param handle             ::HSM_CLIENT_HANDLE that was created by the ::HSM_CLIENT_CREATE call
* @param data               Data that will need to be hashed
* @param data_size          The size of the data parameter
* @param[out] digest        The returned digest. This function allocates memory for a buffer
*                           which must be freed by a call to ::HSM_CLIENT_FREE_BUFFER.
* @param[out] digest_size   The size of the returned digest
*
* @return                   On success 0 on. Non-zero on failure
*/
int hsm_client_tpm_sign_data(
    HSM_CLIENT_HANDLE handle,
    const unsigned char* data_to_be_signed, size_t data_to_be_signed_size,
    unsigned char** digest, size_t* digest_size
);
typedef int (*HSM_CLIENT_SIGN_WITH_IDENTITY)(HSM_CLIENT_HANDLE handle, const unsigned char* data, size_t data_size, unsigned char** digest, size_t* digest_size);

// Table of function pointers (used by tests)
typedef struct HSM_CLIENT_TPM_INTERFACE_TAG
{
    HSM_CLIENT_CREATE hsm_client_tpm_create;
    HSM_CLIENT_DESTROY hsm_client_tpm_destroy;

    HSM_CLIENT_ACTIVATE_IDENTITY_KEY hsm_client_activate_identity_key;
    HSM_CLIENT_GET_ENDORSEMENT_KEY hsm_client_get_ek;
    HSM_CLIENT_GET_STORAGE_ROOT_KEY hsm_client_get_srk;
    HSM_CLIENT_SIGN_WITH_IDENTITY hsm_client_sign_with_identity;
    HSM_CLIENT_FREE_BUFFER hsm_client_free_buffer;
} HSM_CLIENT_TPM_INTERFACE;

const HSM_CLIENT_TPM_INTERFACE* hsm_client_tpm_interface();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HSM_CLIENT_DATA_H
