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
                            let mut credential = engine.credentials.pop().unwrap();

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
                "certificate has unexpectedly changed since last renewal".to_string(),
            ));
        }
    } else {
        return Err(crate::Error::Fatal(
            "could not calculate cert digest".to_string(),
        ));
    }

    let new_cert = credential
        .interface
        .renew_cert(&old_cert, &credential.key_id)
        .await?;

    credential.reset(&new_cert)?;
    credential.interface.renewal_callback().await;

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

    let cert = interface.get_cert(cert_id).await?;

    if policy.threshold.should_renew(&cert) {
        // TODO: Renew cert.
    }

    let credential = crate::Credential::new(cert_id, &cert, key_id, policy, interface)?;

    if let Some(expiry) = engine.credentials.push(credential) {
        engine
            .reschedule_tx
            .send(expiry)
            .map_err(|_| crate::Error::fatal_error("reschedule_rx unexpectedly dropped"))?;
    }

    Ok(())
}
