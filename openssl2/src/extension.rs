// Copyright (c) Microsoft. All rights reserved.

pub fn parse(
    ext: &openssl::x509::X509ExtensionRef,
) -> (openssl::nid::Nid, &openssl::asn1::Asn1BitStringRef) {
    let ptr = foreign_types_shared::ForeignTypeRef::as_ptr(ext);

    let obj = unsafe { openssl_sys2::X509_EXTENSION_get_object(ptr) };
    let obj: &openssl::asn1::Asn1ObjectRef =
        unsafe { foreign_types_shared::ForeignTypeRef::from_ptr(obj) };

    let data = unsafe { openssl_sys2::X509_EXTENSION_get_data(ptr) };
    let data = unsafe { foreign_types_shared::ForeignTypeRef::from_ptr(data) };

    (obj.nid(), data)
}
