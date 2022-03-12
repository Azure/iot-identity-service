// Copyright (c) Microsoft. All rights reserved.

#[async_trait::async_trait]
pub trait CertInterface {
    async fn get_cert(&mut self, cert_id: &str) -> Result<openssl::x509::X509, crate::Error>;
    async fn renew_cert(
        &mut self,
        old_cert: &openssl::x509::X509,
        key_id: &str,
    ) -> Result<openssl::x509::X509, crate::Error>;
    async fn renewal_callback(&mut self);
}
