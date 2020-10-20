// Copyright (c) Microsoft. All rights reserved.

//! `asn1.h`

extern "C" {
    /// Deserializes a DER-encoded octet string.
    ///
    /// The various subtypes of ASN1_STRING, such as ASN1_OCTET_STRING, are just typedefs to ASN1_STRING.
    /// They only exist so that the DER functions, such as d2i_ASN1_OCTET_STRING, are unique for the corresponding DER type.
    ///
    /// So despite being called d2i_ASN1_OCTET_STRING, this function really does operate on ASN1_STRING instances.
    pub fn d2i_ASN1_OCTET_STRING(
        a: *mut *mut openssl_sys::ASN1_STRING,
        ppin: *mut *const std::os::raw::c_char,
        length: std::os::raw::c_long,
    ) -> *mut openssl_sys::ASN1_STRING;
}
