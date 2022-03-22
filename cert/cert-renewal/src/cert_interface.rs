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
#[derive(Clone, Debug)]
pub(crate) struct TestInterface {
    pub keys: std::collections::BTreeMap<String, openssl::pkey::PKey<openssl::pkey::Private>>,
    pub certs: std::collections::BTreeMap<String, openssl::x509::X509>,
    pub lifetime: i64,
    pub renew_err: Option<crate::Error>,
}

#[cfg(test)]
type ArcMutex<T> = std::sync::Arc<futures_util::lock::Mutex<T>>;

#[cfg(test)]
pub(crate) mod test_interface {
    use super::{ArcMutex, TestInterface};

    pub(crate) fn new() -> ArcMutex<TestInterface> {
        let interface = TestInterface {
            keys: std::collections::BTreeMap::default(),
            certs: std::collections::BTreeMap::default(),
            lifetime: 100, // 100 seconds
            renew_err: None,
        };

        let interface = futures_util::lock::Mutex::new(interface);

        std::sync::Arc::new(interface)
    }

    pub(crate) async fn new_cert(
        interface: &ArcMutex<TestInterface>,
        cert_id: &str,
        key_id: &str,
        common_name: &str,
        not_before: i64,
        not_after: i64,
    ) -> openssl::x509::X509 {
        let mut interface = interface.lock().await;

        let (cert, key) = test_common::credential::custom_test_certificate("test_cert", |cert| {
            let mut name = openssl::x509::X509Name::builder().unwrap();
            name.append_entry_by_text("CN", common_name).unwrap();
            let name = name.build();
            cert.set_subject_name(&name).unwrap();

            let not_before = openssl::asn1::Asn1Time::from_unix(not_before).unwrap();
            let not_after = openssl::asn1::Asn1Time::from_unix(not_after).unwrap();

            cert.set_not_before(&not_before).unwrap();
            cert.set_not_after(&not_after).unwrap();
        });

        interface.certs.insert(cert_id.to_string(), cert.clone());
        interface.keys.insert(key_id.to_string(), key);

        cert
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl CertInterface for ArcMutex<TestInterface> {
    type NewKey = openssl::pkey::PKey<openssl::pkey::Private>;

    async fn get_cert(&mut self, cert_id: &str) -> Result<openssl::x509::X509, crate::Error> {
        let interface = self.lock().await;

        if let Some(cert) = interface.certs.get(cert_id) {
            Ok(cert.clone())
        } else {
            Err(crate::Error::retryable_error("failed to get cert"))
        }
    }

    async fn get_key(
        &mut self,
        key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, crate::Error> {
        let interface = self.lock().await;

        if let Some(key) = interface.keys.get(key_id) {
            Ok(key.clone())
        } else {
            Err(crate::Error::retryable_error("failed to get key"))
        }
    }

    async fn renew_cert(
        &mut self,
        old_cert: &openssl::x509::X509,
        _key_id: &str,
    ) -> Result<(openssl::x509::X509, Self::NewKey), crate::Error> {
        let interface = self.lock().await;

        if let Some(err) = &interface.renew_err {
            Err(err.clone())
        } else {
            Ok(test_common::credential::custom_test_certificate(
                // This is ignored as the subject name, but still used as the issuer name.
                "test-cert",
                |cert| {
                    cert.set_subject_name(old_cert.subject_name()).unwrap();

                    let now = i64::from(crate::Time::now());

                    let not_before = openssl::asn1::Asn1Time::from_unix(now).unwrap();
                    cert.set_not_before(&not_before).unwrap();

                    let not_after = now + interface.lifetime;
                    let not_after = openssl::asn1::Asn1Time::from_unix(not_after).unwrap();
                    cert.set_not_after(&not_after).unwrap();
                },
            ))
        }
    }

    async fn write_credentials(
        &mut self,
        _old_cert: &openssl::x509::X509,
        new_cert: (&str, &openssl::x509::X509),
        key: (&str, Self::NewKey),
    ) -> Result<(), crate::Error> {
        let mut interface = self.lock().await;

        interface
            .certs
            .insert(new_cert.0.to_string(), new_cert.1.clone())
            .unwrap();
        interface.keys.insert(key.0.to_string(), key.1).unwrap();

        Ok(())
    }
}
