// Copyright (c) Microsoft. All rights reserved.

//! `x509.h`

extern "C" {
    pub fn X509_check_private_key(
        x509: *const openssl_sys::X509,
        pkey: *const openssl_sys::EVP_PKEY,
    ) -> std::os::raw::c_int;
}
