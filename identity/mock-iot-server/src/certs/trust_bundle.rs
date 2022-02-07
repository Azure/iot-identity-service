// Copyright (c) Microsoft. All rights reserved.

pub(crate) fn read_trust_bundle(
    trust_bundle_certs_dir: Option<&std::path::PathBuf>,
) -> Option<aziot_cloud_client_async::dps::schema::TrustBundle> {
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

            let trust_bundle_cert =
                aziot_cloud_client_async::dps::schema::Certificate { certificate };

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

    Some(aziot_cloud_client_async::dps::schema::TrustBundle { certificates })
}
