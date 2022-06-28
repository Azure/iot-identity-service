// Copyright (c) Microsoft. All rights reserved.

//! `x509.h`

extern "C" {
    pub fn X509_check_private_key(
        x509: *const openssl_sys::X509,
        pkey: *const openssl_sys::EVP_PKEY,
    ) -> std::os::raw::c_int;

    pub fn X509_EXTENSION_get_data(
        ext: *mut openssl_sys::X509_EXTENSION,
    ) -> *mut openssl_sys::ASN1_BIT_STRING;

    pub fn X509_EXTENSION_get_object(
        ext: *mut openssl_sys::X509_EXTENSION,
    ) -> *mut openssl_sys::ASN1_OBJECT;
}
