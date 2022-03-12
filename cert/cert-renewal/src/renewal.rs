// Copyright (c) Microsoft. All rights reserved.

pub(crate) enum Error {
    Fatal(String),
    Retryable(String),
}

pub(crate) async fn renew_credential<I>(
    engine: &mut crate::RenewalEngine<I>,
    credential: &crate::Credential<I>,
) -> Result<crate::Credential<I>, Error>
where
    I: crate::CertInterface,
{
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

    // Get a new key pair and CSR.
    let (private_key, public_key) = new_keys(engine, &credential.key_id).await?;
    let csr = new_csr(&cert, &private_key, &public_key)
        .map_err(|_| Error::Retryable("failed to generate CSR".to_string()))?;

    // TODO: Send CSR to certd for reissuance.
    let cert: openssl::x509::X509 = todo!();

    // Ensure that the new certificate expires in the future.

    let credential = credential
        .reset(&cert)
        .map_err(|_| Error::Retryable("failed to calculate renewals for new cert".to_string()))?;

    // Import the new private key.

    Ok(credential)
}

async fn new_keys<I>(
    engine: &crate::RenewalEngine<I>,
    key_id: &str,
) -> Result<
    (
        openssl::pkey::PKey<openssl::pkey::Private>,
        openssl::pkey::PKey<openssl::pkey::Public>,
    ),
    Error,
>
where
    I: crate::CertInterface,
{
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
            // Attempt to use a key length that matches the current key. If the length cannot
            // be determined, default to 2048-bit key length.
            const DEFAULT_KEY_LENGTH: u32 = 2048;

            let key_length = match key_client
                .get_key_pair_public_parameter(&key_handle, "rsa-modulus")
                .await
            {
                Ok(modulus) => {
                    if let Ok(modulus) = base64::decode(modulus) {
                        u32::try_from(modulus.len() * 8).unwrap_or(DEFAULT_KEY_LENGTH)
                    } else {
                        DEFAULT_KEY_LENGTH
                    }
                }

                Err(_) => DEFAULT_KEY_LENGTH,
            };

            let rsa = openssl::rsa::Rsa::generate(key_length)
                .map_err(|_| Error::Retryable("failed to generate new key".to_string()))?;
            let private_key = openssl::pkey::PKey::from_rsa(rsa)
                .map_err(|_| Error::Retryable("failed to generate new key".to_string()))?;
            let public_key = private_key
                .public_key_to_pem()
                .map_err(|_| Error::Retryable("failed to generate new key".to_string()))?;
            let public_key = openssl::pkey::PKey::public_key_from_pem(&public_key)
                .map_err(|_| Error::Retryable("failed to generate new key".to_string()))?;

            Ok((private_key, public_key))
        }

        _ => Err(Error::Retryable("got unknown key algorithm".to_string())),
    }
}

fn new_csr(
    old_cert: &openssl::x509::X509,
    private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    public_key: &openssl::pkey::PKey<openssl::pkey::Public>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut csr = openssl::x509::X509ReqBuilder::new()?;
    csr.set_version(0)?;

    csr.set_subject_name(old_cert.subject_name())?;
    // TODO: Copy cert extensions.

    csr.set_pubkey(public_key)?;

    // Attempt to use the same signature algorithm as the original cert, but default to
    // SHA-256 if it cannot be determined.
    let algorithm =
        openssl::hash::MessageDigest::from_nid(old_cert.signature_algorithm().object().nid())
            .unwrap_or_else(openssl::hash::MessageDigest::sha256);

    csr.sign(private_key, algorithm)?;

    csr.build().to_pem()
}
