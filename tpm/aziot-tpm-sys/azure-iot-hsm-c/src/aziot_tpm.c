// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/// Derived fom azure-iot-sdk-c library's provisioning client.
/// https://github.com/Azure/azure-iot-sdk-c/blob/master/provisioning_client/src/secure_device_tpm.c

#include <stdlib.h>
#include <stdbool.h>

#include "aziot_tpm.h"
#include "hsm_client_tpm_device.h"

int aziot_tpm_init(int log_level) {
    return hsm_client_tpm_init(log_level);
}

AZIOT_TPM_HANDLE aziot_tpm_create() {
    return (AZIOT_TPM_HANDLE)hsm_client_tpm_create();
}

void aziot_tpm_destroy(AZIOT_TPM_HANDLE handle) {
    return hsm_client_tpm_destroy((HSM_CLIENT_HANDLE)handle);
}

void aziot_tpm_free_buffer(void* buffer) {
    return hsm_client_tpm_free_buffer(buffer);
}

int aziot_tpm_import_auth_key(
    AZIOT_TPM_HANDLE handle,
    const unsigned char* key, size_t key_len
) {
    return hsm_client_tpm_activate_identity_key((HSM_CLIENT_HANDLE)handle, key, key_len);
}

int aziot_tpm_get_keys(
    AZIOT_TPM_HANDLE handle,
    unsigned char** ek, size_t* ek_size,
    unsigned char** srk, size_t* srk_size
) {
    int res;

    res = hsm_client_tpm_get_endorsement_key((HSM_CLIENT_HANDLE)handle, ek, ek_size);
    if (res) {
        return res;
    }
    res = hsm_client_tpm_get_storage_key((HSM_CLIENT_HANDLE)handle, srk, srk_size);
    return res;
}

int aziot_tpm_sign_with_auth_key(
    AZIOT_TPM_HANDLE handle,
    const unsigned char* data, size_t data_size,
    unsigned char** digest, size_t* digest_size
) {
    return hsm_client_tpm_sign_data((HSM_CLIENT_HANDLE)handle, data, data_size, digest, digest_size);
}
