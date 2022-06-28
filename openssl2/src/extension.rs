// Copyright (c) Microsoft. All rights reserved.

pub fn parse(
    ext: &openssl::x509::X509ExtensionRef,
) -> (openssl::nid::Nid, &openssl::asn1::Asn1BitStringRef) {
    let (obj, data): (&openssl::asn1::Asn1ObjectRef, _) = unsafe {
        let ptr = foreign_types_shared::ForeignTypeRef::as_ptr(ext);

        let obj = openssl_sys2::X509_EXTENSION_get_object(ptr);
        let data = openssl_sys2::X509_EXTENSION_get_data(ptr);

        (
            foreign_types_shared::ForeignTypeRef::from_ptr(obj),
            foreign_types_shared::ForeignTypeRef::from_ptr(data),
        )
    };

    (obj.nid(), data)
}
