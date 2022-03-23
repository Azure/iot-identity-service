// Copyright (c) Microsoft. All rights reserved.

type ArcMutex<T> = std::sync::Arc<futures_util::lock::Mutex<T>>;

/// The context used for certificate renewals.
#[allow(clippy::module_name_repetitions)]
pub struct RenewalEngine<I>
where
    I: crate::CertInterface,
{
    credentials: crate::CredentialHeap<I>,
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
                        if credential.next_renewal <= crate::Time::now() {
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
                        log::info!("No certificates left to renew.");

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
        .write_credentials(
            &old_cert,
            (&credential.cert_id, &new_cert),
            (&credential.key_id, key),
        )
        .await?;

    log::info!("Certificate {} was renewed.", credential.cert_id);

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

    log::info!(
        "Certificate {} will be auto-renewed. Next renewal at {}.",
        cert_id,
        credential.next_renewal
    );

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

    let output = match get_cert(
        &mut credential.interface,
        cert_id,
        key_id,
        &credential.policy,
    )
    .await
    {
        Ok((cert, cert_renewed)) => {
            if cert_renewed {
                credential.reset(&cert)?;
            }

            match credential.interface.get_key(key_id).await {
                Ok(key) => Ok((cert, key)),
                Err(crate::Error::Retryable(message)) => {
                    Err(crate::Error::retryable_error(message))
                }
                Err(crate::Error::Fatal(message)) => {
                    return Err(crate::Error::fatal_error(message))
                }
            }
        }
        Err(crate::Error::Retryable(message)) => {
            credential.next_renewal = crate::Time::now() + credential.retry_period;

            Err(crate::Error::retryable_error(message))
        }
        Err(crate::Error::Fatal(message)) => return Err(crate::Error::fatal_error(message)),
    };

    if let Some(expiry) = engine.credentials.push(credential) {
        engine
            .reschedule_tx
            .send(expiry)
            .map_err(|_| crate::Error::fatal_error("reschedule_rx unexpectedly dropped"))?;
    }

    output
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
                    .write_credentials(&cert, (cert_id, &new_cert), (key_id, key))
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

        Err(crate::Error::retryable_error(message))
    } else {
        Ok((cert, cert_renewed))
    }
}

#[cfg(test)]
mod tests {
    use crate::cert_interface::test_interface;
    use crate::{Error, Policy, RenewalPolicy, Time};

    type Interface = super::ArcMutex<crate::TestInterface>;

    fn calculate_digest(cert: &openssl::x509::X509) -> Vec<u8> {
        cert.digest(openssl::hash::MessageDigest::sha256())
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_add_expired() {
        crate::test_time::reset();

        let policy = RenewalPolicy {
            threshold: Policy::Percentage(80),
            retry: Policy::Percentage(4),
        };

        // Add expired cert. This should renew immediately.
        let interface = test_interface::new();
        let cert =
            test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", -101, -1).await;
        let digest = calculate_digest(&cert);

        let engine = super::new::<Interface>();
        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();

        {
            let mut engine = engine.lock().await;
            let credential = engine.credentials.remove("cert-1", "key-1").unwrap();

            assert_eq!(Time::from(80), credential.next_renewal);
            assert_ne!(digest, credential.digest);
            assert_eq!(4, credential.retry_period);
            assert!(engine.credentials.is_empty());
        }

        // Add expired cert that fails to renew. This should cause the API to return an error.
        test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", -101, -1).await;
        test_interface::set_renew_err(&interface, Some(Error::retryable_error("test"))).await;

        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap_err();

        test_interface::set_renew_err(&interface, Some(Error::fatal_error("test"))).await;

        super::add_credential(&engine, "cert-1", "key-1", policy, interface)
            .await
            .unwrap_err();

        {
            let engine = engine.lock().await;

            assert!(engine.credentials.is_empty());
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_add_threshold() {
        crate::test_time::reset();

        let interface = test_interface::new();
        let policy = RenewalPolicy {
            threshold: Policy::Percentage(80),
            retry: Policy::Percentage(4),
        };

        // Add a cert within its renewal threshold. This should renew immediately.
        let cert = test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", -90, 10).await;
        let digest = calculate_digest(&cert);

        let engine = super::new::<Interface>();
        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();

        {
            let mut engine = engine.lock().await;
            let credential = engine.credentials.remove("cert-1", "key-1").unwrap();

            assert_eq!(Time::from(80), credential.next_renewal);
            assert_ne!(digest, credential.digest);
            assert_eq!(4, credential.retry_period);
            assert!(engine.credentials.is_empty());
        }

        // Set cert renewal to fail with a retryable error. This will cause renewal to be
        // scheduled with the retry period.
        let cert = test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", -90, 10).await;
        let digest = calculate_digest(&cert);
        test_interface::set_renew_err(&interface, Some(Error::retryable_error("test"))).await;

        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();

        {
            let mut engine = engine.lock().await;
            let credential = engine.credentials.remove("cert-1", "key-1").unwrap();

            assert_eq!(Time::from(4), credential.next_renewal);
            assert_eq!(digest, credential.digest);
            assert!(engine.credentials.is_empty());
        }

        // Set credential renewal to fail with a fatal error. This should cause the API to
        // return an error.
        test_interface::set_renew_err(&interface, Some(Error::fatal_error("test"))).await;

        super::add_credential(&engine, "cert-1", "key-1", policy, interface)
            .await
            .unwrap_err();

        {
            let engine = engine.lock().await;

            assert!(engine.credentials.is_empty());
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_renew_ok() {
        crate::test_time::reset();

        let interface = test_interface::new();
        let policy = RenewalPolicy {
            threshold: Policy::Percentage(80),
            retry: Policy::Percentage(4),
        };

        // Add test certs to renewal engine.
        let cert_1 = test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", 0, 50).await;
        let cert_1_digest = calculate_digest(&cert_1);

        let cert_2 =
            test_interface::new_cert(&interface, "cert-2", "key-2", "cert-2", 0, 100).await;
        let cert_2_digest = calculate_digest(&cert_2);

        let cert_3 =
            test_interface::new_cert(&interface, "cert-3", "key-3", "cert-3", 0, 200).await;
        let cert_3_digest = calculate_digest(&cert_3);

        let engine = super::new::<Interface>();

        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();
        super::add_credential(
            &engine,
            "cert-2",
            "key-2",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();
        super::add_credential(&engine, "cert-3", "key-3", policy, interface)
            .await
            .unwrap();

        // Advance time to within the renewal threshold and reschedule using a past time. This will
        // immediately trigger the renewal flow.
        crate::test_time::set(85);

        {
            let engine = engine.lock().await;
            engine.reschedule_tx.send(Time::from(84)).unwrap();
        }

        // Allow a short time for cert renewal to run.
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        {
            let mut engine = engine.lock().await;

            let cert_1 = engine.credentials.remove("cert-1", "key-1").unwrap();
            let cert_2 = engine.credentials.remove("cert-2", "key-2").unwrap();
            let cert_3 = engine.credentials.remove("cert-3", "key-3").unwrap();
            assert!(engine.credentials.is_empty());

            // Check that cert-1 and cert-2 were renewed. cert-3 should not have been renewed.
            assert_eq!(Time::from(125), cert_1.next_renewal);
            assert_ne!(cert_1_digest, cert_1.digest);

            assert_eq!(Time::from(165), cert_2.next_renewal);
            assert_ne!(cert_2_digest, cert_2.digest);

            assert_eq!(Time::from(160), cert_3.next_renewal);
            assert_eq!(cert_3_digest, cert_3.digest);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_renew_thumbprints() {
        crate::test_time::reset();

        let interface = test_interface::new();
        let policy = RenewalPolicy {
            threshold: Policy::Percentage(80),
            retry: Policy::Percentage(4),
        };

        test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", 0, 100).await;

        let engine = super::new::<Interface>();
        super::add_credential(&engine, "cert-1", "key-1", policy, interface.clone())
            .await
            .unwrap();

        // Change the stored cert. The renewal engine should detect this change and decline
        // to renew an unknown cert.
        let cert = test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", 0, 100).await;
        let digest = calculate_digest(&cert);

        // Advance time to within the renewal threshold and reschedule using a past time. This will
        // immediately trigger the renewal flow.
        crate::test_time::set(90);

        {
            let engine = engine.lock().await;
            engine.reschedule_tx.send(Time::from(89)).unwrap();
        }

        // Allow a short time for cert renewal to run.
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // Check that the cert was dropped from renewal and not changed in storage.
        {
            let engine = engine.lock().await;

            assert!(engine.credentials.is_empty());
        }

        {
            let interface = interface.lock().await;

            let cert = interface.certs.get("cert-1").unwrap();
            let new_digest = calculate_digest(cert);
            assert_eq!(digest, new_digest);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_renew_err() {
        crate::test_time::reset();

        let interface = test_interface::new();
        let policy = RenewalPolicy {
            threshold: Policy::Percentage(80),
            retry: Policy::Percentage(4),
        };

        // Set renewal to fail with a fatal error.
        test_interface::set_renew_err(&interface, Some(Error::fatal_error("test"))).await;

        // Add test certs to renewal engine.
        test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", 0, 50).await;
        test_interface::new_cert(&interface, "cert-2", "key-2", "cert-2", 0, 100).await;

        let engine = super::new::<Interface>();

        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();
        super::add_credential(&engine, "cert-2", "key-2", policy, interface.clone())
            .await
            .unwrap();

        // Advance time to within the renewal threshold and reschedule using a past time. This will
        // immediately trigger the renewal flow.
        crate::test_time::set(45);

        {
            let engine = engine.lock().await;
            engine.reschedule_tx.send(Time::from(44)).unwrap();
        }

        // Allow a short time for cert renewal to run.
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // Fatal error should cause the certificate to be dropped from renewal.
        {
            let mut engine = engine.lock().await;

            assert!(engine.credentials.remove("cert-1", "key-1").is_none());
        }

        // Set renewal to fail with a retryable error.
        test_interface::set_renew_err(&interface, Some(Error::retryable_error("test"))).await;

        // Advance time to within the renewal threshold and reschedule using a past time. This will
        // immediately trigger the renewal flow.
        crate::test_time::set(95);

        {
            let engine = engine.lock().await;
            engine.reschedule_tx.send(Time::from(94)).unwrap();
        }

        // Allow a short time for cert renewal to run.
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // Retryable error should cause the certificate to be rescheduled using its retry policy.
        {
            let mut engine = engine.lock().await;

            let credential = engine.credentials.remove("cert-2", "key-2").unwrap();
            assert_eq!(Time::from(99), credential.next_renewal);
            assert!(engine.credentials.is_empty());
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_get_expired() {
        crate::test_time::reset();

        let interface = test_interface::new();
        let policy = RenewalPolicy {
            threshold: Policy::Percentage(80),
            retry: Policy::Percentage(4),
        };

        // Add test cert to renewal engine.
        let cert = test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", 0, 50).await;
        let cert_digest = calculate_digest(&cert);

        let engine = super::new::<Interface>();

        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();

        // Get expired cert. This should renew immediately.
        crate::test_time::set(55);

        let (cert, _) = super::get_credential(&engine, "cert-1", "key-1")
            .await
            .unwrap();
        let new_digest = calculate_digest(&cert);
        assert_ne!(cert_digest, new_digest);

        // Check that the renewed cert has its renewal time recalculated.
        {
            let mut engine = engine.lock().await;

            let cert = engine.credentials.remove("cert-1", "key-1").unwrap();
            assert_eq!(Time::from(95), cert.next_renewal);
        }

        // Get expired cert that cannot be renewed. This should cause the API to return an error.
        test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", 0, 50).await;
        test_interface::set_renew_err(&interface, Some(Error::fatal_error("test"))).await;

        crate::test_time::reset();
        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();

        crate::test_time::set(55);
        super::get_credential(&engine, "cert-1", "key-1")
            .await
            .unwrap_err();

        // Fatal error during renewal should cause credential to be dropped.
        {
            let engine = engine.lock().await;

            assert!(engine.credentials.is_empty());
        }

        test_interface::set_renew_err(&interface, None).await;
        crate::test_time::reset();
        super::add_credential(
            &engine,
            "cert-1",
            "key-1",
            policy.clone(),
            interface.clone(),
        )
        .await
        .unwrap();

        // Retryable error should cause the certificate to be rescheduled using its retry policy.
        test_interface::set_renew_err(&interface, Some(Error::retryable_error("test"))).await;
        crate::test_time::set(55);
        super::get_credential(&engine, "cert-1", "key-1")
            .await
            .unwrap_err();

        {
            let mut engine = engine.lock().await;

            let cert = engine.credentials.remove("cert-1", "key-1").unwrap();
            assert_eq!(Time::from(57), cert.next_renewal);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_get_threshold() {
        crate::test_time::reset();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn engine_get_err() {
        crate::test_time::reset();

        let interface = test_interface::new();
        let policy = RenewalPolicy {
            threshold: Policy::Percentage(80),
            retry: Policy::Percentage(4),
        };

        let engine = super::new::<Interface>();

        // Get cert not in renewal engine.
        super::get_credential(&engine, "cert-2", "key-2")
            .await
            .unwrap_err();

        // Get cert where the key is not available.
        test_interface::new_cert(&interface, "cert-1", "key-1", "cert-1", 0, 50).await;

        super::add_credential(&engine, "cert-1", "key-1", policy, interface.clone())
            .await
            .unwrap();

        {
            let mut interface = interface.lock().await;

            interface.keys.remove("key-1").unwrap();
        }

        super::get_credential(&engine, "cert-1", "key-1")
            .await
            .unwrap_err();

        // Check that a key retrieval error did not affect cert renewal time.
        {
            let mut engine = engine.lock().await;

            let cert = engine.credentials.remove("cert-1", "key-1").unwrap();
            assert_eq!(Time::from(40), cert.next_renewal);
        }
    }
}
