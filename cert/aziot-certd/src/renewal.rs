// Copyright (c) Microsoft. All rights reserved.

use std::sync::Arc;

use futures_util::lock::Mutex;

pub(crate) struct EstIdRenewal {
    api: Arc<Mutex<crate::Api>>,
}

impl EstIdRenewal {
    pub fn new(api: Arc<Mutex<crate::Api>>) -> EstIdRenewal {
        EstIdRenewal { api }
    }
}

#[async_trait::async_trait]
impl cert_renewal::CertInterface for EstIdRenewal {
    type NewKey = String;

    async fn get_cert(
        &mut self,
        cert_id: &str,
    ) -> Result<openssl::x509::X509, cert_renewal::Error> {
        let mut api = self.api.lock().await;

        let cert = api
            .get_cert(cert_id)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to retrieve cert"))?;

        openssl::x509::X509::from_pem(&cert)
            .map_err(|_| cert_renewal::Error::fatal_error("failed to parse cert"))
    }

    async fn get_key(
        &mut self,
        key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, cert_renewal::Error> {
        let mut api = self.api.lock().await;

        let key_handle = api
            .key_client
            .load_key_pair(key_id)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to get cert key"))?;

        let key_handle = std::ffi::CString::new(key_handle.0)
            .map_err(|_| cert_renewal::Error::fatal_error("bad key handle"))?;

        api.key_engine
            .load_private_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load cert key"))
    }

    async fn renew_cert(
        &mut self,
        old_cert: &openssl::x509::X509,
        key_id: &str,
    ) -> Result<(openssl::x509::X509, Self::NewKey), cert_renewal::Error> {
        todo!()
    }

    async fn write_credentials(
        &mut self,
        old_cert: &openssl::x509::X509,
        new_cert: (&str, &openssl::x509::X509),
        key: (&str, Self::NewKey),
    ) -> Result<(), cert_renewal::Error> {
        todo!()
    }
}
