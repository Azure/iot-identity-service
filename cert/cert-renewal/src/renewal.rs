// Copyright (c) Microsoft. All rights reserved.

pub(crate) enum Error {
    Fatal(String),
    Retryable(String),
}

pub(crate) async fn renew_credential(
    engine: &mut crate::RenewalEngine,
    credential: &crate::Credential,
) -> Result<crate::Credential, Error> {
    log::info!("Attempting to renew certificate {}.", credential.cert_id);

    // Get the cert to renew.
    let cert = {
        let cert_client = engine.cert_client.lock().await;
        cert_client.get_cert(&credential.cert_id).await
    };

    let cert = if let Ok(cert) = cert {
        if let Ok(cert) = openssl::x509::X509::from_pem(&cert) {
            cert
        } else {
            return Err(Error::Fatal("could not parse cert".to_string()));
        }
    } else {
        return Err(Error::Retryable("could not get cert".to_string()));
    };

    // Check that the cert digest is the same as the last renewal. Renew certs only if the digests match.
    if let Ok(digest) = cert.digest(openssl::hash::MessageDigest::sha256()) {
        if digest.to_vec() != credential.digest {
            return Err(Error::Fatal(
                "certificate has unexpectedly changed since last renewal".to_string(),
            ));
        }
    } else {
        return Err(Error::Fatal("could not calculate cert digest".to_string()));
    }

    // Get a new key pair.
    let (private_key, public_key) = new_keys(engine, &credential.key_id).await?;

    todo!()
}

async fn new_keys(
    engine: &crate::RenewalEngine,
    key_id: &str,
) -> Result<
    (
        openssl::pkey::PKey<openssl::pkey::Private>,
        openssl::pkey::PKey<openssl::pkey::Public>,
    ),
    Error,
> {
    let key_client = engine.key_client.lock().await;

    let key_handle = key_client
        .load_key_pair(key_id)
        .await
        .map_err(|_| Error::Retryable(format!("failed to load private key {}", key_id)))?;

    // Generate a new key with the same algorithm as the existing key.
    match key_client
        .get_key_pair_public_parameter(&key_handle, "algorithm")
        .await
        .map_err(|_| Error::Retryable(format!("failed to get {} key algorithm", key_id)))?
        .as_str()
    {
        "ECDSA" => {
            todo!()
        }

        "RSA" => {
            todo!()
        }

        _ => Err(Error::Retryable("got unknown key algorithm".to_string())),
    }
}
