// Copyright (c) Microsoft. All rights reserved.

#[async_trait::async_trait]
pub trait CertInterface {
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
    ) -> Result<
        (
            openssl::x509::X509,
            openssl::pkey::PKey<openssl::pkey::Private>,
        ),
        crate::Error,
    >;

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
        cert: (&str, &openssl::x509::X509),
        key: (&str, &openssl::pkey::PKey<openssl::pkey::Private>),
    ) -> Result<(), crate::Error>;
}

#[cfg(test)]
pub(crate) struct TestInterface {}

#[cfg(test)]
impl TestInterface {
    pub fn new() -> Self {
        TestInterface {}
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl CertInterface for TestInterface {
    async fn get_cert(&mut self, _cert_id: &str) -> Result<openssl::x509::X509, crate::Error> {
        todo!()
    }

    async fn get_key(
        &mut self,
        _key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, crate::Error> {
        todo!()
    }

    async fn renew_cert(
        &mut self,
        _old_cert: &openssl::x509::X509,
        _key_id: &str,
    ) -> Result<
        (
            openssl::x509::X509,
            openssl::pkey::PKey<openssl::pkey::Private>,
        ),
        crate::Error,
    > {
        todo!()
    }

    async fn write_credentials(
        &mut self,
        _cert: (&str, &openssl::x509::X509),
        _key: (&str, &openssl::pkey::PKey<openssl::pkey::Private>),
    ) -> Result<(), crate::Error> {
        todo!()
    }
}
