// Copyright (c) Microsoft. All rights reserved.

pub(crate) fn issue_cert(csr: &openssl::x509::X509Req) -> String {
    let subject_name = csr.subject_name();
    let public_key = csr.public_key().unwrap();

    let mut cert = openssl::x509::X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(subject_name).unwrap();
    cert.set_pubkey(&public_key).unwrap();

    let mut issuer_name = openssl::x509::X509Name::builder().unwrap();
    issuer_name
        .append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "mock-iot-server ca")
        .unwrap();
    let issuer_name = issuer_name.build();
    cert.set_issuer_name(&issuer_name).unwrap();

    let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
    let not_after = openssl::asn1::Asn1Time::days_from_now(30).unwrap();
    cert.set_not_before(&not_before).unwrap();
    cert.set_not_after(&not_after).unwrap();

    let mut basic_constraints = openssl::x509::extension::BasicConstraints::new();
    basic_constraints.critical();
    let basic_constraints = basic_constraints.build().unwrap();
    cert.append_extension(basic_constraints).unwrap();

    let mut key_usage = openssl::x509::extension::KeyUsage::new();
    key_usage.critical();
    key_usage.digital_signature();
    key_usage.non_repudiation();
    key_usage.key_agreement();
    let key_usage = key_usage.build().unwrap();
    cert.append_extension(key_usage).unwrap();

    let mut ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new();
    ext_key_usage.critical();
    ext_key_usage.client_auth();
    let ext_key_usage = ext_key_usage.build().unwrap();
    cert.append_extension(ext_key_usage).unwrap();

    // mock-iot-server does not authenticate the client. So it's fine to sign
    // the identity certificate with any arbitrary key.
    let (issuer_key, _) = test_common::credential::new_keys();
    cert.sign(&issuer_key, openssl::hash::MessageDigest::sha256())
        .unwrap();

    let cert = cert.build().to_pem().unwrap();

    String::from_utf8(cert).unwrap()
}
