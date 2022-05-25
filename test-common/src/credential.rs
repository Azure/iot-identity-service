// Copyright (c) Microsoft. All rights reserved.

/// Generate a new private key and public key.
pub fn new_keys() -> (
    openssl::pkey::PKey<openssl::pkey::Private>,
    openssl::pkey::PKey<openssl::pkey::Public>,
) {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let private_key = openssl::pkey::PKey::from_rsa(rsa).unwrap();

    let public_key = private_key.public_key_to_pem().unwrap();
    let public_key = openssl::pkey::PKey::public_key_from_pem(&public_key).unwrap();

    (private_key, public_key)
}

/// Generate a CSR for testing.
pub fn test_csr(
    common_name: &str,
) -> (
    openssl::x509::X509Req,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    let (private_key, public_key) = new_keys();
    let mut csr = build_csr(common_name, &public_key);

    csr.sign(&private_key, openssl::hash::MessageDigest::sha256())
        .unwrap();

    (csr.build(), private_key)
}

/// Generate a CSR for testing.
///
/// The `customize` parameter is an optional function that can be used to
/// override the test defaults before the CSR is signed.
pub fn custom_test_csr(
    common_name: &str,
    customize: impl FnOnce(&mut openssl::x509::X509ReqBuilder),
) -> (
    openssl::x509::X509Req,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    let (private_key, public_key) = new_keys();
    let mut csr = build_csr(common_name, &public_key);

    customize(&mut csr);

    csr.sign(&private_key, openssl::hash::MessageDigest::sha256())
        .unwrap();

    (csr.build(), private_key)
}

/// Generate a self-signed cert for testing.
pub fn test_certificate(
    common_name: &str,
) -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    let (private_key, public_key) = new_keys();
    let mut cert = build_cert(common_name, &public_key);

    cert.sign(&private_key, openssl::hash::MessageDigest::sha256())
        .unwrap();

    (cert.build(), private_key)
}

/// Generate a self-signed cert for testing.
///
/// The `customize` parameter is an optional function that can be used to
/// override the test defaults before the certificate is signed.
pub fn custom_test_certificate(
    common_name: &str,
    customize: impl FnOnce(&mut openssl::x509::X509Builder),
) -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    let (private_key, public_key) = new_keys();
    let mut cert = build_cert(common_name, &public_key);

    customize(&mut cert);

    cert.sign(&private_key, openssl::hash::MessageDigest::sha256())
        .unwrap();

    (cert.build(), private_key)
}

fn build_csr(
    common_name: &str,
    public_key: &openssl::pkey::PKey<openssl::pkey::Public>,
) -> openssl::x509::X509ReqBuilder {
    let name = name(common_name);

    let mut csr = openssl::x509::X509Req::builder().unwrap();

    csr.set_subject_name(&name).unwrap();
    csr.set_pubkey(public_key).unwrap();

    csr
}

fn build_cert(
    common_name: &str,
    public_key: &openssl::pkey::PKey<openssl::pkey::Public>,
) -> openssl::x509::X509Builder {
    let name = name(common_name);

    let mut cert = openssl::x509::X509::builder().unwrap();

    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(public_key).unwrap();

    let not_before = openssl::asn1::Asn1Time::from_unix(0).unwrap();
    let not_after = openssl::asn1::Asn1Time::days_from_now(30).unwrap();

    cert.set_not_before(&not_before).unwrap();
    cert.set_not_after(&not_after).unwrap();

    cert
}

fn name(common_name: &str) -> openssl::x509::X509Name {
    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();

    name.build()
}
