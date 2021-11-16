// Copyright (c) Microsoft. All rights reserved.

fn fmt_common_name(name: &openssl::x509::X509NameRef) -> String {
    let common_name = name
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .unwrap()
        .data();

    format!("CN={}", common_name.as_utf8().unwrap())
}

fn fmt_time(time: &openssl::asn1::Asn1TimeRef) -> String {
    let epoch = openssl::asn1::Asn1Time::from_unix(0).unwrap();
    let diff = epoch.diff(time).unwrap();

    assert!(diff.days > 0);
    assert!(diff.secs > 0);
    let timestamp = i64::from(diff.days) * 86400 + i64::from(diff.secs);

    let time = chrono::NaiveDateTime::from_timestamp(timestamp, 0);
    let time = chrono::DateTime::<chrono::Utc>::from_utc(time, chrono::Utc);

    time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn fmt_thumbprint(cert: &openssl::x509::X509, hash_type: openssl::hash::MessageDigest) -> String {
    let thumbprint = cert.digest(hash_type).unwrap();
    let thumbprint = openssl::bn::BigNum::from_slice(&thumbprint).unwrap();

    thumbprint.to_hex_str().unwrap().to_string()
}

pub(crate) fn read_trust_bundle(
    trust_bundle_certs_dir: Option<std::path::PathBuf>,
) -> Option<aziot_dps_client_async::model::TrustBundle> {
    let trust_bundle_certs_dir = if let Some(dir) = trust_bundle_certs_dir {
        assert!(dir.is_dir());

        dir
    } else {
        return None;
    };

    println!("Building trust bundle.");

    let mut certificates = vec![];

    for file in std::fs::read_dir(trust_bundle_certs_dir).unwrap() {
        let file = file.unwrap();

        if file.path().is_dir() {
            continue;
        }

        let pem = std::fs::read_to_string(file.path()).unwrap();
        let cert_stack = openssl::x509::X509::stack_from_pem(pem.as_bytes()).unwrap();

        if cert_stack.is_empty() {
            println!(
                "Ignoring {} (contains no certificates).",
                file.path().to_str().unwrap()
            );

            continue;
        }

        println!(
            "Adding {} certificate(s) from {}",
            cert_stack.len(),
            file.path().to_str().unwrap()
        );

        for cert in cert_stack {
            let certificate = cert.to_pem().unwrap();
            let certificate = String::from_utf8(certificate).unwrap();

            let subject_name = fmt_common_name(cert.subject_name());
            let issuer_name = fmt_common_name(cert.issuer_name());
            println!(" - {}", subject_name);

            let serial_number = cert.serial_number().to_bn().unwrap();
            let serial_number = serial_number.to_hex_str().unwrap().to_string();

            let metadata = aziot_dps_client_async::model::X509CertificateInfo {
                subject_name,
                sha1_thumbprint: fmt_thumbprint(&cert, openssl::hash::MessageDigest::sha1()),
                sha256_thumbprint: fmt_thumbprint(&cert, openssl::hash::MessageDigest::sha256()),
                issuer_name,
                not_before_utc: fmt_time(cert.not_before()),
                not_after_utc: fmt_time(cert.not_after()),
                serial_number,
                version: cert.version() + 1,
            };

            let trust_bundle_cert = aziot_dps_client_async::model::TrustBundleCertificate {
                certificate,
                metadata,
            };

            certificates.push(trust_bundle_cert);
        }
    }

    assert!(
        !certificates.is_empty(),
        "Trust bundle directory contains no certificates."
    );
    println!(
        "Contructed trust bundle with {} certificates.",
        certificates.len()
    );

    Some(aziot_dps_client_async::model::TrustBundle { certificates })
}
