// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

#[cfg(not(test))]
use aziot_cert_client_async::Client as CertClient;

#[cfg(test)]
use test_common::client::CertClient;

#[cfg(not(test))]
use aziot_key_client_async::Client as KeyClient;

#[cfg(test)]
use test_common::client::KeyClient;

type ArcMutex<T> = std::sync::Arc<futures_util::lock::Mutex<T>>;

/// The context used for certificate renewals.
#[allow(clippy::module_name_repetitions)]
pub struct RenewalEngine {
    credentials: crate::credential::CredentialHeap,
    reschedule_tx: tokio::sync::mpsc::UnboundedSender<crate::Time>,
    key_client: ArcMutex<KeyClient>,
    cert_client: ArcMutex<CertClient>,
}

async fn renewal_loop(
    engine: ArcMutex<RenewalEngine>,
    mut reschedule_rx: tokio::sync::mpsc::UnboundedReceiver<crate::Time>,
) {
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
                // TODO: renew credentials.
                todo!()
            }
        };
    }
}

/// Create a new renewal engine.
pub fn new(
    key_client: ArcMutex<KeyClient>,
    cert_client: ArcMutex<CertClient>,
) -> ArcMutex<RenewalEngine> {
    let (reschedule_tx, reschedule_rx) = tokio::sync::mpsc::unbounded_channel();

    let engine = RenewalEngine {
        credentials: crate::credential::CredentialHeap::new(),
        reschedule_tx,
        key_client,
        cert_client,
    };

    let engine = std::sync::Arc::new(futures_util::lock::Mutex::new(engine));
    let renewal_engine = engine.clone();

    tokio::spawn(async move {
        renewal_loop(renewal_engine, reschedule_rx).await;
    });

    engine
}

/// Add an existing certificate to the renewal engine.
pub async fn add_cert(
    engine: &ArcMutex<RenewalEngine>,
    cert_id: &str,
    key_id: &str,
    policy: crate::RenewalPolicy,
) -> Result<(), Error> {
    let mut engine = engine.lock().await;

    let cert = {
        let cert_client = engine.cert_client.lock().await;

        let cert = cert_client.get_cert(cert_id).await?;

        openssl::x509::X509::from_pem(&cert)
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?
    };

    if policy.threshold.should_renew(&cert) {
        // TODO: Renew cert.
    }

    let credential = crate::credential::Credential::new(cert_id, &cert, key_id, policy)?;

    if let Some(expiry) = engine.credentials.push(credential) {
        engine
            .reschedule_tx
            .send(expiry)
            .map_err(|_| Error::new(ErrorKind::BrokenPipe, "reschedule_rx unexpectedly dropped"))?;
    }

    Ok(())
}
