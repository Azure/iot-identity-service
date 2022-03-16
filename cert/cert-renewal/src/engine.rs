// Copyright (c) Microsoft. All rights reserved.

type ArcMutex<T> = std::sync::Arc<futures_util::lock::Mutex<T>>;

/// The context used for certificate renewals.
#[allow(clippy::module_name_repetitions)]
pub struct RenewalEngine<I>
where
    I: crate::CertInterface,
{
    pub(crate) credentials: crate::CredentialHeap<I>,
    reschedule_tx: tokio::sync::mpsc::UnboundedSender<crate::Time>,
}

async fn renewal_loop<I>(
    engine: ArcMutex<RenewalEngine<I>>,
    mut reschedule_rx: tokio::sync::mpsc::UnboundedReceiver<crate::Time>,
) where
    I: crate::CertInterface,
{
    let mut renewal_time = crate::Time::forever();

    loop {
        let next_reschedule = reschedule_rx.recv();
        tokio::pin!(next_reschedule);

        let next_deadline = renewal_time.sleep_until();
        tokio::pin!(next_deadline);

        // Wait for the next renewal time or for a reschedule.
        renewal_time = match futures_util::future::select(next_reschedule, next_deadline).await {
            futures_util::future::Either::Left((expiry, _)) => {
                if let Some(expiry) = expiry {
                    expiry
                } else {
                    // Exit if sender was dropped.
                    return;
                }
            }

            futures_util::future::Either::Right((_, _)) => {
                let mut engine = engine.lock().await;

                loop {
                    if let Some(credential) = engine.credentials.peek() {
                        // Account for inaccuracies with sleep timing by renewing any credential that
                        // expires within the next minute.
                        if credential.next_renewal <= crate::Time::now() + 60 {
                            // Credential heap was peeked, so there should be a credential to pop.
                            let mut credential = engine.credentials.remove_next().unwrap();

                            match renew_cert(&mut credential).await {
                                // Successful renewal: schedule next renewal per policy.
                                Ok(()) => {
                                    engine.credentials.push(credential);
                                }

                                // Retryable error: schedule retry per policy.
                                Err(crate::Error::Retryable(message)) => {
                                    let next_retry = crate::Time::now() + credential.retry_period;

                                    log::warn!(
                                        "Tried to renew {}, but {}. Retrying at {}.",
                                        credential.cert_id,
                                        message,
                                        next_retry
                                    );

                                    credential.next_renewal = next_retry;
                                    engine.credentials.push(credential);
                                }

                                // Fatal error: drop this credential from future renewal.
                                Err(crate::Error::Fatal(message)) => {
                                    log::warn!(
                                        "Tried to renew {}, but {}. {} will no longer be auto-renewed.",
                                        credential.cert_id,
                                        message,
                                        credential.cert_id
                                    );
                                }
                            }
                        } else {
                            // This credential is not near renewal time. Reschedule timer for its renewal.
                            break credential.next_renewal;
                        }
                    } else {
                        // No credentials are available to renew. Wait indefinitely for the next one to be added.
                        log::warn!("Certificate renewal triggered, but no certificates are available to renew.");

                        break crate::Time::forever();
                    };
                }
            }
        };
    }
}

async fn renew_cert<I>(credential: &mut crate::Credential<I>) -> Result<(), crate::Error>
where
    I: crate::CertInterface,
{
    log::info!("Attempting to renew certificate {}.", credential.cert_id);

    let old_cert = credential.interface.get_cert(&credential.cert_id).await?;

    // Check that the cert digest is the same as the last renewal. Renew certs only if the digests match.
    if let Ok(digest) = old_cert.digest(openssl::hash::MessageDigest::sha256()) {
        if digest.to_vec() != credential.digest {
            return Err(crate::Error::Fatal(
                "certificate has changed since last renewal".to_string(),
            ));
        }
    } else {
        return Err(crate::Error::Fatal(
            "could not calculate cert digest".to_string(),
        ));
    }

    let (new_cert, key) = credential
        .interface
        .renew_cert(&old_cert, &credential.key_id)
        .await?;

    // This function may fail if `new_cert` is invalid or expired. Map these failures
    // to `Retryable` errors; discard `new_cert` and fall back to `old_cert` for now.
    credential
        .reset(&new_cert)
        .map_err(|err| crate::Error::Retryable(err.to_string()))?;

    credential
        .interface
        .write_credentials((&credential.cert_id, &new_cert), (&credential.key_id, key))
        .await?;

    Ok(())
}

/// Create a new renewal engine.
pub fn new<I>() -> ArcMutex<RenewalEngine<I>>
where
    I: crate::CertInterface + Send + Sync + 'static,
{
    let (reschedule_tx, reschedule_rx) = tokio::sync::mpsc::unbounded_channel();

    let engine = RenewalEngine {
        credentials: crate::CredentialHeap::new(),
        reschedule_tx,
    };

    let engine = std::sync::Arc::new(futures_util::lock::Mutex::new(engine));
    let renewal_engine = engine.clone();

    tokio::spawn(async move {
        renewal_loop(renewal_engine, reschedule_rx).await;
    });

    engine
}

/// Add an existing certificate and key to the renewal engine.
pub async fn add_credential<I>(
    engine: &ArcMutex<RenewalEngine<I>>,
    cert_id: &str,
    key_id: &str,
    policy: crate::RenewalPolicy,
    mut interface: I,
) -> Result<(), crate::Error>
where
    I: crate::CertInterface,
{
    let mut engine = engine.lock().await;

    let (cert, _) = get_cert(&mut interface, cert_id, key_id, &policy).await?;
    let credential = crate::Credential::new(cert_id, &cert, key_id, policy, interface)?;

    if let Some(expiry) = engine.credentials.push(credential) {
        engine
            .reschedule_tx
            .send(expiry)
            .map_err(|_| crate::Error::fatal_error("reschedule_rx unexpectedly dropped"))?;
    }

    Ok(())
}

/// Retrieve a certificate and key from the renewal engine.
///
/// It is not strictly necessary to use this function (`cert_id` and `key_id` could be
/// retrieved directly from Certificates and Keys Services). However, retrieving credentials
/// with this function will ensure that credentials are not retrieved mid-renewal and that
/// the retrieved credentials are valid.
pub async fn get_credential<I>(
    engine: &ArcMutex<RenewalEngine<I>>,
    cert_id: &str,
    key_id: &str,
) -> Result<
    (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ),
    crate::Error,
>
where
    I: crate::CertInterface + Clone,
{
    let mut engine = engine.lock().await;

    let mut credential = if let Some(credential) = engine.credentials.remove(cert_id, key_id) {
        credential
    } else {
        return Err(crate::Error::fatal_error(format!("{} not found", cert_id)));
    };

    let (cert, cert_renewed) = get_cert(
        &mut credential.interface,
        cert_id,
        key_id,
        &credential.policy,
    )
    .await?;
    let key = credential.interface.get_key(key_id).await?;

    if cert_renewed {
        credential.reset(&cert)?;
    }

    if let Some(expiry) = engine.credentials.push(credential) {
        engine
            .reschedule_tx
            .send(expiry)
            .map_err(|_| crate::Error::fatal_error("reschedule_rx unexpectedly dropped"))?;
    }

    Ok((cert, key))
}

async fn get_cert<I>(
    interface: &mut I,
    cert_id: &str,
    key_id: &str,
    policy: &crate::RenewalPolicy,
) -> Result<(openssl::x509::X509, bool), crate::Error>
where
    I: crate::CertInterface,
{
    let mut cert = interface.get_cert(cert_id).await?;
    let mut cert_renewed = false;

    if policy.threshold.should_renew(&cert) {
        match interface.renew_cert(&cert, key_id).await {
            Ok((new_cert, key)) => {
                match interface
                    .write_credentials((cert_id, &new_cert), (key_id, key))
                    .await
                {
                    Ok(()) => {
                        cert = new_cert;
                        cert_renewed = true;
                    }
                    Err(crate::Error::Retryable(message)) => {
                        log::warn!(
                            "Tried to renew {}, but failed to write new cert: {}.",
                            cert_id,
                            message
                        );
                    }
                    Err(crate::Error::Fatal(message)) => {
                        log::error!("Failed to write new cert {}: {}.", cert_id, message);

                        return Err(crate::Error::fatal_error(message));
                    }
                }
            }
            Err(crate::Error::Retryable(message)) => {
                log::warn!("Tried to renew {}, but {}.", cert_id, message);
            }
            Err(crate::Error::Fatal(message)) => {
                log::error!(
                    "Failed to initialize cert renewal for {}: {}.",
                    cert_id,
                    message
                );

                return Err(crate::Error::fatal_error(message));
            }
        };
    }

    let expiry = crate::Time::from(cert.not_after());

    if expiry.in_past() {
        let message = format!("Cert {} is expired and could not be renewed", cert_id);
        log::error!("{}.", message);

        return Err(crate::Error::fatal_error(message));
    }

    Ok((cert, cert_renewed))
}
