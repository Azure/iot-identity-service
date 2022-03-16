// Copyright (c) Microsoft. All rights reserved.

#[async_trait::async_trait]
pub trait CertInterface {
    /// Represents a key used for a new certificate. Initially returned from cert renewal as a
    /// temporary key, and later written to persistent storage with the renewed cert.
    type NewKey: Send + Sync;

    /// Retrieve a certificate from the provided `cert_id`.
    async fn get_cert(&mut self, cert_id: &str) -> Result<openssl::x509::X509, crate::Error>;

    /// Retrieve a private key from the provided `key_id`.
    async fn get_key(
        &mut self,
        key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, crate::Error>;

    /// Renew the provided certificate.
    ///
    /// This function should renew `old_cert` and its key and return the renewed certificate and
    /// key. It MUST leave `old_cert` and its key intact upon returning; i.e. it must not erase
    /// `old_cert` or its key.
    ///
    /// After this function returns, the renewal engine needs to perform additional checks and
    /// calculations on the renewed certificate. If the renewal engine determines the new certificate
    /// to be invalid, it will discard the renewed certificate and fall back to the old credentials.
    ///
    /// Once the renewal engine determines the renewed certificate to be valid, it will call
    /// `write_credentials`. The old certificate and its key may then be overwritten.
    async fn renew_cert(
        &mut self,
        old_cert: &openssl::x509::X509,
        key_id: &str,
    ) -> Result<(openssl::x509::X509, Self::NewKey), crate::Error>;

    /// Write the new credentials to storage, replacing any existing credentials with the same IDs.
    ///
    /// This function is called when certificate renewal has successfully completed. It should write
    /// the provided credentials to storage, committing them as the new versions of the provided IDs.
    ///
    /// If any credential write fails, this function must revert and previous changes it made and
    /// return an error. For example, if writing `cert` succeeds but writing `key` fails, then this
    /// function must revert any changes to `cert` before returning an error.
    async fn write_credentials(
        &mut self,
        old_cert: &openssl::x509::X509,
        new_cert: (&str, &openssl::x509::X509),
        key: (&str, Self::NewKey),
    ) -> Result<(), crate::Error>;
}

#[cfg(test)]
pub(crate) struct TestInterface {
    pub keys: std::collections::BTreeMap<String, openssl::pkey::PKey<openssl::pkey::Private>>,
    pub certs: std::collections::BTreeMap<String, openssl::x509::X509>,
}

#[cfg(test)]
impl TestInterface {
    pub fn new() -> Self {
        TestInterface {
            keys: std::collections::BTreeMap::default(),
            certs: std::collections::BTreeMap::default(),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl CertInterface for TestInterface {
    type NewKey = openssl::pkey::PKey<openssl::pkey::Private>;

    #[allow(clippy::unused_async)]
    async fn get_cert(&mut self, cert_id: &str) -> Result<openssl::x509::X509, crate::Error> {
        if let Some(cert) = self.certs.get(cert_id) {
            Ok(cert.clone())
        } else {
            Err(crate::Error::retryable_error("failed to get cert"))
        }
    }

    #[allow(clippy::unused_async)]
    async fn get_key(
        &mut self,
        key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, crate::Error> {
        if let Some(key) = self.keys.get(key_id) {
            Ok(key.clone())
        } else {
            Err(crate::Error::retryable_error("failed to get key"))
        }
    }

    #[allow(clippy::unused_async)]
    async fn renew_cert(
        &mut self,
        old_cert: &openssl::x509::X509,
        _key_id: &str,
    ) -> Result<(openssl::x509::X509, Self::NewKey), crate::Error> {
        Ok(test_common::credential::custom_test_certificate(
            "test-cert", // This is ignored and replaced below.
            |cert| {
                cert.set_subject_name(old_cert.subject_name()).unwrap();
            },
        ))
    }

    #[allow(clippy::unused_async)]
    async fn write_credentials(
        &mut self,
        _old_cert: &openssl::x509::X509,
        new_cert: (&str, &openssl::x509::X509),
        key: (&str, Self::NewKey),
    ) -> Result<(), crate::Error> {
        self.certs
            .insert(new_cert.0.to_string(), new_cert.1.clone())
            .unwrap();
        self.keys.insert(key.0.to_string(), key.1).unwrap();

        Ok(())
    }
}
